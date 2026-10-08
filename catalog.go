package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

const (
	maxSkillFiles    = 512
	maxSkillBytes    = 16 << 20
	maxManifestBytes = 32 << 20
	maxPointerBytes  = 1 << 20
)

type skillEntry struct {
	URI         string          `json:"uri"`
	Frontmatter map[string]any  `json:"frontmatter"`
	Resources   []skillResource `json:"resources"`
}

type skillResource struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

var errNotFound = errors.New("resource not found")

type catalogStore struct {
	root string
}

type catalogSnapshot struct {
	Catalog string       `json:"catalog"`
	Skills  []skillEntry `json:"skills"`
}

type scannedCatalog struct {
	Name   string         `json:"name"`
	Skills []scannedSkill `json:"skills"`
}

type scannedSkill struct {
	RelDir      string         `json:"relative_dir"`
	Frontmatter map[string]any `json:"frontmatter"`
	Files       []scannedFile  `json:"files"`
}

type scannedFile struct {
	RelPath string `json:"path"`
	Digest  string `json:"digest"`
	Size    int64  `json:"size"`
	Data    []byte `json:"-"`
}

type currentPointer map[string]string

// publishCatalogs snapshots every source before atomically switching the global pointer.
func publishCatalogs(c config) (map[string]string, error) {
	if len(c.Catalogs) == 0 {
		return nil, errors.New("at least one catalog is required")
	}
	storeRoot, err := filepath.Abs(c.Store)
	if err != nil {
		return nil, err
	}
	if err := rejectSourceStoreOverlap(storeRoot, c.Catalogs); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(storeRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create catalog store: %w", err)
	}
	if err := requireDirectory(storeRoot); err != nil {
		return nil, fmt.Errorf("catalog store: %w", err)
	}

	catalogs := make([]catalogConfig, len(c.Catalogs))
	copy(catalogs, c.Catalogs)
	sort.Slice(catalogs, func(i, j int) bool { return catalogs[i].Name < catalogs[j].Name })

	scanned := make([]scannedCatalog, 0, len(catalogs))
	seen := map[string]bool{}
	for _, cfg := range catalogs {
		if !validCatalogName(cfg.Name) || seen[cfg.Name] {
			return nil, fmt.Errorf("invalid or duplicate catalog %q", cfg.Name)
		}
		seen[cfg.Name] = true
		source, err := filepath.Abs(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("catalog %s: %w", cfg.Name, err)
		}
		cat, err := scanCatalog(cfg.Name, source)
		if err != nil {
			return nil, err
		}
		scanned = append(scanned, cat)
	}

	seed := struct {
		Catalogs []scannedCatalog `json:"catalogs"`
	}{Catalogs: scanned}
	seedBytes, err := json.Marshal(seed)
	if err != nil {
		return nil, fmt.Errorf("catalog revision: %w", err)
	}
	h := sha256.Sum256(seedBytes)
	revision := hex.EncodeToString(h[:])

	objectsRoot := filepath.Join(storeRoot, "objects")
	snapshotsRoot := filepath.Join(storeRoot, "snapshots", revision)
	if err := os.MkdirAll(objectsRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create object store: %w", err)
	}
	if err := os.MkdirAll(snapshotsRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot store: %w", err)
	}
	if err := requireDirectory(objectsRoot); err != nil {
		return nil, err
	}
	if err := requireDirectory(snapshotsRoot); err != nil {
		return nil, err
	}

	pointer := make(currentPointer, len(scanned))
	for _, cat := range scanned {
		entries := make([]skillEntry, 0, len(cat.Skills))
		for _, skill := range cat.Skills {
			entry := skillEntry{
				URI:         skillURI(cat.Name, revision, skill.RelDir, "SKILL.md"),
				Frontmatter: skill.Frontmatter,
			}
			for _, file := range skill.Files {
				if err := ensureImmutable(filepath.Join(objectsRoot, file.Digest[len("sha256:"):]), file.Data); err != nil {
					return nil, err
				}
				entry.Resources = append(entry.Resources, skillResource{
					URI:    skillURI(cat.Name, revision, skill.RelDir, file.RelPath),
					Digest: file.Digest,
					Size:   file.Size,
				})
			}
			entries = append(entries, entry)
		}
		manifestBytes, err := json.Marshal(catalogSnapshot{Catalog: cat.Name, Skills: entries})
		if err != nil {
			return nil, fmt.Errorf("catalog %s manifest: %w", cat.Name, err)
		}
		if len(manifestBytes) > maxManifestBytes {
			return nil, fmt.Errorf("catalog %s manifest exceeds size limit", cat.Name)
		}
		if err := ensureImmutable(filepath.Join(snapshotsRoot, cat.Name+".json"), manifestBytes); err != nil {
			return nil, err
		}
		pointer[cat.Name] = revision
	}

	pointerBytes, err := json.Marshal(pointer)
	if err != nil {
		return nil, err
	}
	if len(pointerBytes) > maxPointerBytes {
		return nil, errors.New("catalog pointer exceeds size limit")
	}
	if err := atomicReplace(filepath.Join(storeRoot, "current.json"), pointerBytes); err != nil {
		return nil, fmt.Errorf("publish catalog pointer: %w", err)
	}
	return map[string]string(pointer), nil
}

func (s *catalogStore) list(allowed []string) ([]skillEntry, error) {
	pointer, err := s.current()
	if err != nil {
		return nil, err
	}
	catalogs := append([]string(nil), allowed...)
	sort.Strings(catalogs)
	var result []skillEntry
	for _, catalog := range catalogs {
		revision, ok := pointer[catalog]
		if !ok {
			continue
		}
		manifest, err := s.loadSnapshot(catalog, revision)
		if err != nil {
			return nil, err
		}
		result = append(result, manifest.Skills...)
	}
	return result, nil
}

func (s *catalogStore) get(uri string, allowed []string) (skillEntry, error) {
	manifest, canonical, err := s.authorizedSnapshot(uri, allowed)
	if err != nil {
		return skillEntry{}, err
	}
	for _, entry := range manifest.Skills {
		if entry.URI == canonical {
			return entry, nil
		}
	}
	return skillEntry{}, errNotFound
}

func (s *catalogStore) read(uri string, allowed []string) (*mcp.ResourceContents, error) {
	manifest, canonical, err := s.authorizedSnapshot(uri, allowed)
	if err != nil {
		return nil, err
	}
	var resource skillResource
	found := false
	for _, entry := range manifest.Skills {
		for _, candidate := range entry.Resources {
			if candidate.URI == canonical {
				resource, found = candidate, true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nil, errNotFound
	}
	data, err := s.readObject(resource)
	if err != nil {
		return nil, err
	}
	contents := &mcp.ResourceContents{URI: canonical}
	if len(data) == 0 {
		contents.Blob = []byte{}
	} else if utf8.Valid(data) {
		contents.Text = string(data)
	} else {
		contents.Blob = data
	}
	return contents, nil
}

func (s *catalogStore) authorizedSnapshot(uri string, allowed []string) (catalogSnapshot, string, error) {
	catalog, revision, canonical, ok := parseSkillURI(uri)
	if !ok || !slices.Contains(allowed, catalog) {
		return catalogSnapshot{}, "", errNotFound
	}
	snapshot, err := s.loadSnapshot(catalog, revision)
	if errors.Is(err, os.ErrNotExist) {
		err = errNotFound
	}
	return snapshot, canonical, err
}

func (s *catalogStore) current() (currentPointer, error) {
	data, err := readRootedFile(s.root, "current.json", maxPointerBytes)
	if err != nil {
		return nil, err
	}
	var pointer currentPointer
	if err := json.Unmarshal(data, &pointer); err != nil {
		return nil, fmt.Errorf("read catalog pointer: %w", err)
	}
	if pointer == nil {
		return nil, errors.New("invalid catalog pointer")
	}
	for catalog, revision := range pointer {
		if !validCatalogName(catalog) || !revisionPattern(revision) {
			return nil, errors.New("invalid catalog pointer")
		}
	}
	return pointer, nil
}

func readRootedFile(dir, name string, max int64) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular store file", name)
	}
	return readRegularFS(root.FS(), name, max, info)
}

func (s *catalogStore) loadSnapshot(catalog, revision string) (catalogSnapshot, error) {
	if !validCatalogName(catalog) || !revisionPattern(revision) {
		return catalogSnapshot{}, errNotFound
	}
	data, err := readRootedFile(s.root, pathpkg.Join("snapshots", revision, catalog+".json"), maxManifestBytes)
	if err != nil {
		return catalogSnapshot{}, err
	}
	var snapshot catalogSnapshot
	if err := decodeJSON(data, &snapshot); err != nil {
		return catalogSnapshot{}, fmt.Errorf("read catalog snapshot: %w", err)
	}
	if snapshot.Catalog != catalog {
		return catalogSnapshot{}, errors.New("catalog snapshot mismatch")
	}
	return snapshot, nil
}

func (s *catalogStore) readObject(resource skillResource) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(resource.Digest, prefix) || len(resource.Digest) != len(prefix)+64 {
		return nil, errors.New("invalid resource digest")
	}
	digest := resource.Digest[len(prefix):]
	if _, err := hex.DecodeString(digest); err != nil {
		return nil, errors.New("invalid resource digest")
	}
	if resource.Size < 0 || resource.Size > maxSkillBytes {
		return nil, errors.New("invalid resource size")
	}
	data, err := readRootedFile(s.root, pathpkg.Join("objects", digest), resource.Size+1)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != resource.Size {
		return nil, errors.New("resource size mismatch")
	}
	h := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(h[:]) != resource.Digest {
		return nil, errors.New("resource digest mismatch")
	}
	return data, nil
}

func scanCatalog(name, source string) (scannedCatalog, error) {
	if err := requireDirectory(source); err != nil {
		return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
	}
	defer root.Close()
	fsys := root.FS()
	skillDirs, err := discoverSkillDirs(fsys)
	if err != nil {
		return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
	}
	if len(skillDirs) == 0 {
		return scannedCatalog{}, fmt.Errorf("catalog %s has no skills", name)
	}
	rootPrefix := ""
	rootSkill := slices.Contains(skillDirs, ".")
	if rootSkill {
		data, err := readRegularFS(fsys, "SKILL.md", maxSkillBytes, nil)
		if err != nil {
			return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
		}
		frontmatter, err := parseFrontmatter(data)
		if err != nil {
			return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
		}
		rootPrefix, err = validateSkillFrontmatter(frontmatter)
		if err != nil {
			return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
		}
	}
	result := scannedCatalog{Name: name, Skills: make([]scannedSkill, 0, len(skillDirs))}
	for _, dir := range skillDirs {
		logical := dir
		if rootSkill {
			if dir == "." {
				logical = rootPrefix
			} else {
				logical = pathpkg.Join(rootPrefix, dir)
			}
		}
		skill, err := scanSkill(fsys, dir, logical)
		if err != nil {
			return scannedCatalog{}, fmt.Errorf("catalog %s: %w", name, err)
		}
		result.Skills = append(result.Skills, skill)
	}
	return result, nil
}

func discoverSkillDirs(fsys fs.FS) ([]string, error) {
	var dirs []string
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink %s is not allowed", name)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", name)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", name)
		}
		if entry.Name() == "SKILL.md" {
			dirs = append(dirs, pathpkg.Dir(name))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(dirs)
	return dirs, nil
}

func scanSkill(fsys fs.FS, dir, logicalDir string) (scannedSkill, error) {
	if logicalDir == "" || logicalDir == "." || !fs.ValidPath(dir) && dir != "." {
		return scannedSkill{}, errors.New("invalid skill directory")
	}
	var result scannedSkill
	result.RelDir = logicalDir
	var total int64
	var count int
	err := fs.WalkDir(fsys, dir, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return fs.SkipDir
			}

			if entry.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("symlink %s is not allowed", name)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", name)
			}
			return nil
		}
		if entry.Name() == ".git" {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink %s is not allowed", name)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("skill file %s is not a regular file", name)
		}
		count++
		if count > maxSkillFiles {
			return errors.New("skill has too many files")
		}
		remaining := int64(maxSkillBytes) - total
		if info.Size() < 0 || info.Size() > remaining {
			return errors.New("skill exceeds size limit")
		}
		data, err := readRegularFS(fsys, name, remaining, info)
		if err != nil {
			return err
		}
		total += int64(len(data))
		digest := sha256.Sum256(data)
		rel := strings.TrimPrefix(name, dir+"/")
		if !fs.ValidPath(rel) {
			return errors.New("skill file path escapes skill")
		}
		result.Files = append(result.Files, scannedFile{
			RelPath: rel,
			Digest:  "sha256:" + hex.EncodeToString(digest[:]),
			Size:    int64(len(data)),
			Data:    data,
		})
		if rel == "SKILL.md" {
			frontmatter, err := parseFrontmatter(data)
			if err != nil {
				return err
			}
			nameValue, err := validateSkillFrontmatter(frontmatter)
			if err != nil {
				return err
			}
			if pathpkg.Base(result.RelDir) != nameValue {
				return fmt.Errorf("frontmatter name %q does not match skill directory", nameValue)
			}
			result.Frontmatter = frontmatter
		}
		return nil
	})
	if err != nil {
		return scannedSkill{}, err
	}
	if result.Frontmatter == nil {
		return scannedSkill{}, errors.New("missing SKILL.md")
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].RelPath < result.Files[j].RelPath })
	return result, nil
}

func validateSkillFrontmatter(frontmatter map[string]any) (string, error) {
	name, ok := frontmatter["name"].(string)
	if !ok || name == "" {
		return "", errors.New("frontmatter name is required")
	}
	if !validSkillName(name) {
		return "", errors.New("invalid frontmatter name")
	}
	description, ok := frontmatter["description"].(string)
	if !ok || description == "" || utf8.RuneCountInString(description) > 1024 {
		return "", errors.New("invalid frontmatter description")
	}
	return name, nil
}

func validSkillName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 64 ||
		strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") || strings.Contains(name, "--") {
		return false
	}
	for _, r := range name {
		if r != '-' && ((!unicode.IsLetter(r) && !unicode.IsNumber(r)) || unicode.ToLower(r) != r) {
			return false
		}
	}
	return true
}

func parseFrontmatter(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("SKILL.md is not valid UTF-8")
	}
	line := func(pos int) (string, int) {
		end := bytes.IndexByte(data[pos:], '\n')
		if end < 0 {
			end = len(data)
		} else {
			end += pos
		}
		text := strings.TrimSuffix(string(data[pos:end]), "\r")
		next := end
		if next < len(data) {
			next++
		}
		return text, next
	}
	first, pos := line(0)
	if first != "---" {
		return nil, errors.New("missing frontmatter")
	}
	start := pos
	end := -1
	for pos < len(data) {
		text, next := line(pos)
		if text == "---" {
			end = pos
			break
		}
		pos = next
	}
	if end < 0 {
		return nil, errors.New("unterminated frontmatter")
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data[start:end], &raw); err != nil {
		return nil, fmt.Errorf("invalid frontmatter: %w", err)
	}
	if raw == nil {
		return nil, errors.New("frontmatter must be a mapping")
	}
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("frontmatter is not JSON-compatible: %w", err)
	}
	var normalized map[string]any
	if err := decodeJSON(jsonBytes, &normalized); err != nil {
		return nil, fmt.Errorf("frontmatter is not JSON-compatible: %w", err)
	}
	return normalized, nil
}

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("expected one JSON document")
		}
		return err
	}
	return nil
}

func skillURI(catalog, revision, relDir, relPath string) string {
	parts := []string{"skill:", "", catalog, revision}
	for _, part := range strings.Split(pathpkg.Join(relDir, relPath), "/") {
		parts = append(parts, url.PathEscape(part))
	}
	return strings.Join(parts, "/")
}

func parseSkillURI(raw string) (catalog, revision, canonical string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "skill" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", "", "", false
	}
	if !validCatalogName(u.Host) {
		return "", "", "", false
	}
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, "/") {
		return "", "", "", false
	}
	rawParts := strings.Split(strings.TrimPrefix(escaped, "/"), "/")
	if len(rawParts) < 3 {
		return "", "", "", false
	}
	parts := make([]string, len(rawParts))
	for i, part := range rawParts {
		if part == "" {
			return "", "", "", false
		}
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || strings.Contains(decoded, "/") || strings.Contains(decoded, "\\") {
			return "", "", "", false
		}
		parts[i] = decoded
	}
	if !revisionPattern(parts[0]) {
		return "", "", "", false
	}
	catalog, revision = u.Host, parts[0]
	canonicalParts := make([]string, 0, len(parts))
	for _, part := range parts {
		canonicalParts = append(canonicalParts, url.PathEscape(part))
	}
	canonical = "skill://" + catalog + "/" + strings.Join(canonicalParts, "/")
	return catalog, revision, canonical, true
}

func revisionPattern(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func requireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func readRegularFS(fsys fs.FS, name string, max int64, expected fs.FileInfo) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || (expected != nil && (!os.SameFile(expected, opened) || expected.Size() != opened.Size())) {
		return nil, fmt.Errorf("%s is not the expected regular file", name)
	}
	if opened.Size() < 0 || opened.Size() > max {
		return nil, errors.New("file exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("file exceeds size limit")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

func ensureImmutable(path string, data []byte) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	existing, err := readRootedFile(dir, name, int64(len(data))+1)
	if errors.Is(err, os.ErrNotExist) {
		if err := writeImmutable(path, data); !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, err = readRootedFile(dir, name, int64(len(data))+1)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, data) {
		return fmt.Errorf("immutable file %s has changed", path)
	}
	return nil
}

func writeImmutable(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".immutable-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Link(tempName, path)
}

func atomicReplace(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".current-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func rejectSourceStoreOverlap(store string, catalogs []catalogConfig) error {
	storeReal, err := resolvedPath(store)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	for _, catalog := range catalogs {
		source, err := filepath.Abs(catalog.Path)
		if err != nil {
			return err
		}
		sourceReal, err := filepath.EvalSymlinks(source)
		if err != nil {
			return fmt.Errorf("catalog %s: %w", catalog.Name, err)
		}
		if within(source, store) || within(store, source) || within(sourceReal, storeReal) || within(storeReal, sourceReal) {
			return fmt.Errorf("catalog source and store must not overlap")
		}
	}
	return nil
}

func resolvedPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	parent, base := filepath.Split(abs)
	if parent == abs {
		return abs, nil
	}
	resolvedParent, err := resolvedPath(filepath.Clean(parent))
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, base), nil
}
