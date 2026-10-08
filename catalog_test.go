package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogPublicationPreservesPinnedRevision(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(filepath.Join(source, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldSkill := "---\nname: demo\ndescription: first\ntags:\n  - one\n---\nold body\n"
	if err := os.WriteFile(filepath.Join(source, "demo", "SKILL.md"), []byte(oldSkill), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "demo", "data.bin"), []byte{0xff, 0x80}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "demo", "empty.txt"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	c := config{Store: store, Catalogs: []catalogConfig{{Name: "main", Path: source}}}
	start := make(chan struct{})
	published := make(chan error, 8)
	for range cap(published) {
		go func() {
			<-start
			_, err := publishCatalogs(c)
			published <- err
		}()
	}
	close(start)
	for range cap(published) {
		if err := <-published; err != nil {
			t.Errorf("concurrent publication: %v", err)
		}
	}
	first, err := publishCatalogs(c)
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := publishCatalogs(c); err != nil || repeated["main"] != first["main"] {
		t.Fatalf("unchanged publication changed revision: %v, %v", repeated, err)
	}
	st := &catalogStore{root: store}
	oldEntries, err := st.list([]string{"main"})
	if err != nil || len(oldEntries) != 1 {
		t.Fatalf("list old: %v, %d entries", err, len(oldEntries))
	}
	oldURI := oldEntries[0].URI
	oldContents, err := st.read(oldURI, []string{"main"})
	if err != nil || oldContents.Text != oldSkill {
		t.Fatalf("read old: %v", err)
	}
	var binaryURI, binaryDigest, emptyURI string
	for _, resource := range oldEntries[0].Resources {
		if strings.HasSuffix(resource.URI, "/data.bin") {
			binaryURI = resource.URI
			binaryDigest = resource.Digest
		}
		if strings.HasSuffix(resource.URI, "/empty.txt") {
			emptyURI = resource.URI
		}
	}
	if binaryURI == "" {
		t.Fatal("binary resource missing from manifest")
	}
	binaryContents, err := st.read(binaryURI, []string{"main"})
	if err != nil || !bytes.Equal(binaryContents.Blob, []byte{0xff, 0x80}) {
		t.Fatalf("read binary: %v", err)
	}
	if emptyURI == "" {
		t.Fatal("empty resource missing from manifest")
	}
	emptyContents, err := st.read(emptyURI, []string{"main"})
	if err != nil || emptyContents.Blob == nil || len(emptyContents.Blob) != 0 {
		t.Fatalf("read empty: %v", err)
	}

	newSkill := "---\nname: demo\ndescription: second\ntags:\n  - two\n---\nnew body\n"
	if err := os.WriteFile(filepath.Join(source, "demo", "SKILL.md"), []byte(newSkill), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := publishCatalogs(c)
	if err != nil {
		t.Fatal(err)
	}
	if first["main"] == second["main"] {
		t.Fatal("revision did not change")
	}
	newEntries, err := st.list([]string{"main"})
	if err != nil || len(newEntries) != 1 {
		t.Fatalf("list new: %v, %d entries", err, len(newEntries))
	}
	if newEntries[0].URI == oldURI {
		t.Fatal("new entry reused old URI")
	}
	oldContents, err = st.read(oldURI, []string{"main"})
	if err != nil || oldContents.Text != oldSkill {
		t.Fatalf("pinned read changed: %v", err)
	}
	newContents, err := st.read(newEntries[0].URI, []string{"main"})
	if err != nil || newContents.Text != newSkill {
		t.Fatalf("new read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store, "objects", strings.TrimPrefix(binaryDigest, "sha256:")), []byte{0, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.read(binaryURI, []string{"main"}); err == nil {
		t.Fatal("tampered blob was accepted")
	}
	current, err := os.ReadFile(filepath.Join(store, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishCatalogs(c); err == nil {
		t.Fatal("publication accepted a conflicting immutable object")
	}
	after, err := os.ReadFile(filepath.Join(store, "current.json"))
	if err != nil || !bytes.Equal(current, after) {
		t.Fatalf("conflicting object advanced the current pointer: %v", err)
	}
}

func TestCatalogAuthorizationAndSymlinkRejection(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	catalogs := []catalogConfig{
		{Name: "one", Path: filepath.Join(root, "one")},
		{Name: "two", Path: filepath.Join(root, "two")},
	}
	for _, catalog := range catalogs {
		dir := filepath.Join(catalog.Path, catalog.Name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + catalog.Name + "\ndescription: skill\n---\n" + catalog.Name + "\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	published, err := publishCatalogs(config{Store: store, Catalogs: catalogs})
	if err != nil {
		t.Fatal(err)
	}
	st := &catalogStore{root: store}
	entries, err := st.list([]string{"one"})
	if err != nil || len(entries) != 1 {
		t.Fatalf("authorized list: %v", err)
	}
	twoEntries, err := st.list([]string{"two"})
	if err != nil || len(twoEntries) != 1 {
		t.Fatalf("second list: %v", err)
	}
	if _, err := st.get(twoEntries[0].URI, []string{"one"}); !errors.Is(err, errNotFound) {
		t.Fatalf("unauthorized get error = %v", err)
	}
	if _, err := st.read(twoEntries[0].URI, []string{"one"}); !errors.Is(err, errNotFound) {
		t.Fatalf("unauthorized read error = %v", err)
	}
	traversal := "skill://one/" + published["one"] + "/one/../secret/SKILL.md"
	if _, err := st.get(traversal, []string{"one"}); !errors.Is(err, errNotFound) {
		t.Fatalf("traversal error = %v", err)
	}

	linkTarget := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(linkTarget, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, filepath.Join(catalogs[0].Path, catalogs[0].Name, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := publishCatalogs(config{Store: store, Catalogs: catalogs}); err == nil {
		t.Fatal("symlinked supporting file was published")
	}
}

func TestCatalogRejectsMalformedFrontmatter(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source", "bad")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("not frontmatter\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := publishCatalogs(config{
		Store:    filepath.Join(root, "store"),
		Catalogs: []catalogConfig{{Name: "main", Path: filepath.Dir(source)}},
	})
	if err == nil {
		t.Fatal("malformed frontmatter was accepted")
	}
}
func TestCatalogRecursiveUnicodeAndRootPrefix(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	nested := filepath.Join(source, "sub", "éclair")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("---\nname: racine\ndescription: root\n---\nroot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "SKILL.md"), []byte("---\nname: éclair\ndescription: nested\n---\nnested\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	revisions, err := publishCatalogs(config{
		Store:    filepath.Join(root, "store"),
		Catalogs: []catalogConfig{{Name: "main", Path: source}},
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := (&catalogStore{root: filepath.Join(root, "store")}).list([]string{"main"})
	if err != nil || len(entries) != 2 {
		t.Fatalf("recursive list: %v, %d entries", err, len(entries))
	}
	if !strings.Contains(entries[0].URI, "/"+revisions["main"]+"/racine/") || !strings.Contains(entries[1].URI, "/"+revisions["main"]+"/racine/") {
		t.Fatalf("root prefix missing: %#v", entries)
	}
	if !strings.Contains(entries[0].URI+entries[1].URI, "sub/") {
		t.Fatalf("nested skill missing: %#v", entries)
	}
}

func TestCatalogFailedPublicationKeepsCurrent(t *testing.T) {
	root := t.TempDir()
	validRoot := filepath.Join(root, "valid", "good")
	badRoot := filepath.Join(root, "bad", "bad")
	if err := os.MkdirAll(validRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(badRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(validRoot, "SKILL.md"), []byte("---\nname: good\ndescription: valid\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(root, "store")
	valid := config{Store: store, Catalogs: []catalogConfig{{Name: "valid", Path: filepath.Dir(validRoot)}}}
	if _, err := publishCatalogs(valid); err != nil {
		t.Fatal(err)
	}
	before, err := (&catalogStore{root: store}).list([]string{"valid"})
	if err != nil || len(before) != 1 {
		t.Fatalf("before list: %v", err)
	}
	if err := os.WriteFile(filepath.Join(badRoot, "SKILL.md"), []byte("missing frontmatter\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := config{Store: store, Catalogs: []catalogConfig{
		{Name: "valid", Path: filepath.Dir(validRoot)},
		{Name: "bad", Path: filepath.Dir(badRoot)},
	}}
	if _, err := publishCatalogs(failed); err == nil {
		t.Fatal("invalid publication succeeded")
	}
	after, err := (&catalogStore{root: store}).list([]string{"valid"})
	if err != nil || len(after) != 1 || after[0].URI != before[0].URI {
		t.Fatalf("current pointer changed after failed publication: %v", err)
	}
}
