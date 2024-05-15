package bundle

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"text/template"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/dominikbraun/graph"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/exp/maps"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/ptr"
)

type Entrypoint struct {
	File  string
	Flags []string
}

const entrypointTemplate = `# generated by wolfictl build
set -eux

# TODO: Should this be in the bundle?
melange keygen local-melange.rsa

melange build {{.File}} \
 --gcplog \
{{ range .Flags }} {{.}} \
{{end}}

tar -czvf packages.tar.gz ./packages

# TODO: Content-Type
curl --upload-file packages.tar.gz -H "Content-Type: application/octet-stream" $PACKAGES_UPLOAD_URL

sha256sum packages.tar.gz
sha256sum packages.tar.gz | cut -d' ' -f1 > /dev/termination-log
`

var entrypointTmpl *template.Template

func init() {
	entrypointTmpl = template.Must(template.New("entrypointTemplate").Parse(entrypointTemplate))
}

func renderEntrypoint(entrypoint *Entrypoint) (v1.Layer, error) {
	var tbuf bytes.Buffer
	tw := tar.NewWriter(&tbuf)

	var ebuf bytes.Buffer
	if err := entrypointTmpl.Execute(&ebuf, entrypoint); err != nil {
		return nil, err
	}

	eb := ebuf.Bytes()

	hdr := &tar.Header{
		Name: "entrypoint.sh",
		Mode: 0o755,
		Size: int64(len(eb)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}

	if _, err := tw.Write(eb); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(tbuf.Bytes())), nil
	}

	return tarball.LayerFromOpener(opener)
}

// todo: optimize this if it matters (it probably doesn't)
func layer(srcfs fs.FS) (v1.Layer, error) {
	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)
	if err := tarAddFS(tw, srcfs); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}

	return tarball.LayerFromOpener(opener)
}

func New(base v1.ImageIndex, entrypoints map[types.Architecture]*Entrypoint, commonfiles, srcfs fs.FS) (v1.ImageIndex, error) {
	m, err := base.IndexManifest()
	if err != nil {
		return nil, err
	}

	wantArchs := map[types.Architecture]struct{}{}
	for arch := range entrypoints {
		wantArchs[arch] = struct{}{}
	}

	haveArchs := map[types.Architecture]v1.Descriptor{}
	for _, desc := range m.Manifests { //nolint: gocritic
		haveArchs[types.ParseArchitecture(desc.Platform.Architecture)] = desc
	}

	var idx v1.ImageIndex = empty.Index

	for arch := range wantArchs {
		platform := &v1.Platform{
			OS:           "linux", // TODO: If this is ever wrong, throw a party.
			Architecture: string(arch),
		}

		baseImg := mutate.MediaType(empty.Image, ggcrtypes.OCIManifestSchema1)
		if desc, ok := haveArchs[arch]; ok {
			baseImg, err = base.Image(desc.Digest)
			if err != nil {
				return nil, err
			}
			platform = desc.Platform
		}

		commonLayer, err := layer(commonfiles)
		if err != nil {
			return nil, err
		}

		sourceLayer, err := layer(srcfs)
		if err != nil {
			return nil, err
		}

		// TODO: DO NOT SUBMIT. This is probably wrong.
		entrypoint, ok := entrypoints[arch]
		if !ok {
			return nil, fmt.Errorf("unexpected arch %q for entrypoints: %v", arch, maps.Keys(entrypoints))
		}

		entrypointLayer, err := renderEntrypoint(entrypoint)
		if err != nil {
			return nil, err
		}

		img, err := mutate.AppendLayers(baseImg, commonLayer, sourceLayer, entrypointLayer)
		if err != nil {
			return nil, err
		}

		cf, err := img.ConfigFile()
		if err != nil {
			return nil, err
		}

		cf.Config.Entrypoint = []string{"/bin/sh", "/entrypoint.sh"}
		cf.Config.WorkingDir = "/"

		img, err = mutate.ConfigFile(img, cf)
		if err != nil {
			return nil, err
		}

		newDesc, err := partial.Descriptor(img)
		if err != nil {
			return nil, err
		}

		newDesc.Platform = platform

		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: *newDesc,
		})
	}

	return idx, nil
}

type Bundle struct {
	idx           v1.ImageIndex
	Package       string
	Version       string
	Epoch         uint64
	Architectures []string
}

// Yuck.
type Graph = map[string]map[string]graph.Edge[string]

type Bundles struct {
	idx      v1.ImageIndex
	Graph    Graph
	Packages map[string]name.Digest
}

func (b *Bundles) Bundle(want string) (*Bundle, error) {
	im, err := b.idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	for i, desc := range im.Manifests[1:] { //nolint: gocritic
		pkg, ok := desc.Annotations["dev.wolfi.bundle.package"]
		if !ok {
			return nil, fmt.Errorf("expected package annotation in %dth descriptor", i)
		}
		version, ok := desc.Annotations["dev.wolfi.bundle.version"]
		if !ok {
			return nil, fmt.Errorf("expected package annotation in %dth descriptor", i)
		}
		sepoch, ok := desc.Annotations["dev.wolfi.bundle.epoch"]
		if !ok {
			return nil, fmt.Errorf("expected package annotation in %dth descriptor", i)
		}
		epoch, err := strconv.ParseUint(sepoch, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing epoch: %w", err)
		}

		if pkg == want {
			child, err := b.idx.ImageIndex(desc.Digest)
			if err != nil {
				return nil, err
			}

			cm, err := child.IndexManifest()
			if err != nil {
				return nil, err
			}

			archs := []string{}
			for _, desc := range cm.Manifests { //nolint: gocritic
				archs = append(archs, desc.Platform.Architecture)
			}

			return &Bundle{
				idx:           child,
				Package:       want,
				Version:       version,
				Epoch:         epoch,
				Architectures: archs,
			}, nil
		}
	}

	return nil, fmt.Errorf("could not find package %q", want)
}

// TODO: dependency injection
func Pull(pull string) (*Bundles, error) {
	ref, err := name.ParseReference(pull)
	if err != nil {
		return nil, err
	}

	idx, err := remote.Index(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithUserAgent("wolfictl bundle"))
	if err != nil {
		return nil, err
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	if len(im.Manifests) == 0 {
		return nil, fmt.Errorf("no manifests in bundle index: %s", pull)
	}

	desc := im.Manifests[0]
	img, err := idx.Image(desc.Digest)
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("no layers in first entry %s of bundle %s", desc.Digest.String(), pull)
	}

	rc, err := layers[0].Compressed()
	if err != nil {
		return nil, err
	}

	var g Graph
	if err := json.NewDecoder(rc).Decode(&g); err != nil {
		return nil, err
	}

	pkgs := map[string]name.Digest{}

	for i, desc := range im.Manifests[1:] { //nolint: gocritic
		pkg, ok := desc.Annotations["dev.wolfi.bundle.package"]
		if !ok {
			return nil, fmt.Errorf("expected package annotation in %dth descriptor", i)
		}

		pkgs[pkg] = ref.Context().Digest(desc.Digest.String())
	}

	return &Bundles{
		idx:      idx,
		Graph:    g,
		Packages: pkgs,
	}, nil
}

// escapeRFC1123 escapes a string to be RFC1123 compliant.  We don't worry about
// being collision free because these are generally fed to generateName which
// appends a randomized suffix.
func escapeRFC1123(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", "-"), "_", "-")
}

// Podspec returns bytes of yaml representing a podspec.
// This is a terrible API that we should change.
func Podspec(cfg *config.Configuration, ref name.Reference, arch string) *corev1.Pod {
	goarch := types.ParseArchitecture(arch).String()

	resources := cfg.Package.Resources
	if resources == nil {
		resources = &config.Resources{}
	}

	// Set some sane default resource requests if none are specified by flag or config.
	// This is required for GKE Autopilot.
	if resources.CPU == "" {
		resources.CPU = "2"
	}
	if resources.Memory == "" {
		resources.Memory = "4Gi"
	}

	rr := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(resources.CPU),
			corev1.ResourceMemory: resource.MustParse(resources.Memory),
		},
	}

	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("melange-builder-%s-%s-", escapeRFC1123(cfg.Package.Name), goarch),
			Namespace:    "default",
			Labels: map[string]string{
				"kubernetes.io/arch":             goarch,
				"app.kubernetes.io/component":    cfg.Package.Name,
				"melange.chainguard.dev/arch":    goarch,
				"melange.chainguard.dev/package": cfg.Package.Name,
			},
			Annotations: map[string]string{},
		},
		Spec: corev1.PodSpec{
			// Don't putz around for 30s when we kill things.
			TerminationGracePeriodSeconds: ptr.Int64(0),
			Containers: []corev1.Container{{
				Name:  "workspace",
				Image: ref.String(),
				// TODO: Do we need this??
				// ldconfig is run to prime ld.so.cache for glibc packages which require it.
				// Command:      []string{"/bin/sh", "-c", "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true\nsleep infinity"},
				Resources:    rr,
				VolumeMounts: []corev1.VolumeMount{},
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.Bool(true),
				},
			}},
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr.Bool(false),
			NodeSelector: map[string]string{
				"kubernetes.io/arch": goarch,
			},
			Tolerations: []corev1.Toleration{{
				Effect:   "NoSchedule",
				Key:      "kubernetes.io/arch",
				Operator: "Equal",
				Value:    "arm64",
			}, {
				Effect:   "NoSchedule",
				Key:      "chainguard.dev/runner",
				Operator: "Equal",
				Value:    "bundle-builder",
			}},
			ServiceAccountName: "default",
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Volumes: []corev1.Volume{},
		},
	}

	for k, v := range cfg.Environment.Environment {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	return pod
}

// TODO: Just use tar.Writer.AddFS: https://github.com/golang/go/issues/66831
func tarAddFS(tw *tar.Writer, fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// TODO(#49580): Handle symlinks when fs.ReadLinkFS is available.
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("tar: cannot add non-regular file")
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = name
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := fsys.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}