package configs

import (
	"errors"

	"chainguard.dev/melange/pkg/build"
	"github.com/samber/lo"
)

// A Selection is a view into an Index's configuration entries. The selection can
// expose anywhere from zero entries up to all the index's entries. A selection
// allows the caller to chain methods to further constrain the selection and to
// perform operations on each item in the selection.
type Selection struct {
	entries []Entry
	index   *Index
}

var (
	ErrNoEntriesInSelection       = errors.New("the selection contain 0 entries")
	ErrMultipleEntriesInSelection = errors.New("the operation requires the selection to have one entries but it has multiple entries")
)

func (s Selection) GetConfig() (*build.Configuration, error) {
	if len(s.entries) == 0 {
		return nil, ErrNoEntriesInSelection
	}

	if len(s.entries) > 1 {
		return nil, ErrMultipleEntriesInSelection
	}

	config := s.entries[0].Configuration()
	return config, nil
}

// WherePackageName filters the selection down to entries whose package name
// matches the given parameter.
func (s Selection) WherePackageName(name string) Selection {
	var entries []Entry
	for _, e := range s.entries {
		cfg := e.Configuration()
		if cfg == nil {
			continue
		}
		if name == cfg.Package.Name {
			entries = append(entries, e)
		}
	}

	return Selection{
		entries: entries,
		index:   s.index,
	}
}

// WherePackageOrSubpackageName filters the selection down to entries either
// whose package namees match the given parameter or where there's a subpackage
// whose name matches the given parameter.
func (s Selection) WherePackageOrSubpackageName(name string) Selection {
	var entries []Entry
	for _, e := range s.entries {
		cfg := e.Configuration()
		if cfg == nil {
			continue
		}

		if name == cfg.Package.Name {
			entries = append(entries, e)
		}

		matchingSubpackages := lo.Filter(cfg.Subpackages, func(sp build.Subpackage, _ int) bool {
			return sp.Name == name
		})

		if len(matchingSubpackages) > 0 {
			entries = append(entries, e)
		}
	}

	return Selection{
		entries: entries,
		index:   s.index,
	}
}

// WhereFilePath filters the selection down to entries whose configuration file
// path match the given parameter.
func (s Selection) WhereFilePath(p string) Selection {
	var entries []Entry
	for _, e := range s.entries {
		if p == e.Path() {
			entries = append(entries, e)
		}
	}

	return Selection{
		entries: entries,
		index:   s.index,
	}
}

// Len returns the count of configurations in the Selection.
func (s Selection) Len() int {
	return len(s.entries)
}
