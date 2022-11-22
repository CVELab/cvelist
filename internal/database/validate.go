// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/vuln/client"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/report"
)

func Validate(dbPath string) (err error) {
	derrors.Wrap(&err, "Validate(%s)", dbPath)

	// Load will fail if any files are missing.
	d, err := Load(dbPath)
	if err != nil {
		return err
	}
	if err = d.validate(dbPath); err != nil {
		return err
	}
	return nil
}

func (d *Database) validate(dbPath string) error {
	if err := d.checkNoUnexpectedFiles(dbPath); err != nil {
		return err
	}
	if err := d.checkInternalConsistency(); err != nil {
		return err
	}
	return nil
}

func (d *Database) checkNoUnexpectedFiles(dbPath string) error {
	return filepath.WalkDir(dbPath, func(path string, f fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fname := f.Name()
		ext := filepath.Ext(fname)
		dir := filepath.Dir(path)

		switch {
		// Skip directories.
		case f.IsDir():
			return nil
		// In the top-level directory, web files and index files are OK.
		case dir == dbPath && isIndexOrWebFile(fname, ext):
			return nil
		// All non-directory and non-web files should end in ".json".
		case ext != ".json":
			return fmt.Errorf("found unexpected non-JSON file %s", path)
		// All files in the ID directory (except the index) should have
		// corresponding entries in EntriesByID.
		case dir == filepath.Join(dbPath, idDirectory):
			if fname == indexFile {
				return nil
			}
			id := report.GetGoIDFromFilename(fname)
			if _, ok := d.EntriesByID[id]; !ok {
				return fmt.Errorf("found unexpected ID %q which is not present in %s", id, filepath.Join(idDirectory, indexFile))
			}
		// All other files should have corresponding entries in
		// EntriesByModule.
		default:
			module := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(path, dbPath), "/"), ".json")
			unescaped, err := client.UnescapeModulePath(module)
			if err != nil {
				return fmt.Errorf("could not unescape module file %s: %v", path, err)
			}
			if _, ok := d.EntriesByModule[unescaped]; !ok {
				return fmt.Errorf("found unexpected module %q which is not present in %s", unescaped, indexFile)
			}
		}
		return nil
	})
}

func isIndexOrWebFile(filename, ext string) bool {
	return ext == ".ico" ||
		ext == ".html" ||
		// HTML files may have no extension.
		ext == "" ||
		filename == indexFile ||
		filename == aliasesFile
}

func (d *Database) checkInternalConsistency() error {
	if il, ml := len(d.Index), len(d.EntriesByModule); il != ml {
		return fmt.Errorf("length mismatch: there are %d module entries in the index, and %d module directory entries", il, ml)
	}

	for module, modified := range d.Index {
		entries, ok := d.EntriesByModule[module]
		if !ok || len(entries) == 0 {
			return fmt.Errorf("no module directory found for indexed module %s", module)
		}

		var wantModified time.Time
		for _, entry := range entries {
			if mod := entry.Modified; mod.After(wantModified) {
				wantModified = mod
			}

			entryByID, ok := d.EntriesByID[entry.ID]
			if !ok {
				return fmt.Errorf("no advisory found for ID %s listed in %s", entry.ID, module)
			}
			if !reflect.DeepEqual(entry, entryByID) {
				return fmt.Errorf("inconsistent OSV contents in module and ID advisory for %s", entry.ID)
			}
		}
		if modified != wantModified {
			return fmt.Errorf("incorrect modified timestamp for module %s: want %s, got %s", module, wantModified, modified)
		}
	}

	for id, entry := range d.EntriesByID {
		for _, affected := range entry.Affected {
			module := affected.Package.Name
			entries, ok := d.EntriesByModule[module]
			if !ok || len(entries) == 0 {
				return fmt.Errorf("module %s not found (referenced by %s)", module, id)
			}
			found := false
			for _, gotEntry := range entries {
				if gotEntry.ID == id {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s does not have an entry in %s", id, module)
			}
		}
		for _, alias := range entry.Aliases {
			gotEntries, ok := d.IDsByAlias[alias]
			if !ok || len(gotEntries) == 0 {
				return fmt.Errorf("alias %s not found in aliases.json (alias of %s)", alias, id)
			}
			found := false
			for _, gotID := range gotEntries {
				if gotID == id {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s is not listed as an alias of %s", entry.ID, alias)
			}
		}
	}

	for alias, goIDs := range d.IDsByAlias {
		for _, goID := range goIDs {
			entry, ok := d.EntriesByID[goID]
			if !ok {
				return fmt.Errorf("no advisory found for ID %s listed under %s", goID, alias)
			}

			if !slices.Contains(entry.Aliases, alias) {
				return fmt.Errorf("advisory %s does not reference alias %s", goID, alias)
			}
		}
	}

	return nil
}
