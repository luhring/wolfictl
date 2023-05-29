package advisory

import (
	"io"
	"io/fs"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory/event"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
	"gopkg.in/yaml.v3"
)

func NewIndex(fsys rwfs.FS) (*configs.Index[Document], error) {
	return configs.NewIndex[Document](fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(fsys rwfs.FS, paths ...string) (*configs.Index[Document], error) {
	return configs.NewIndexFromPaths[Document](fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(string) (*Document, error) {
	return func(path string) (*Document, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return nil, err
		}

		return DecodeDocument(file)
	}
}

func DecodeDocument(r io.Reader) (*Document, error) {
	doc := &Document{}
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	err := decoder.Decode(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

type Document struct {
	Package Package `yaml:"package"`

	Advisories Advisories `yaml:"advisories,omitempty"`
}

func (d Document) Name() string {
	return d.Package.Name
}

type Package struct {
	Name string `yaml:"name"`
}

type Advisories map[string]Advisory

// Entry is an entry in an advisory.
//
// Deprecated: Use event.Event instead.
type Entry struct {
	Timestamp       time.Time         `yaml:"timestamp"`
	Status          vex.Status        `yaml:"status"`
	Justification   vex.Justification `yaml:"justification,omitempty"`
	ImpactStatement string            `yaml:"impact,omitempty"`
	ActionStatement string            `yaml:"action,omitempty"`
	FixedVersion    string            `yaml:"fixed-version,omitempty"`
}

type Advisory struct {
	ID     string        `yaml:"id"`
	Events []event.Event `yaml:"events"`
}
