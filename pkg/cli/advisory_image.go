package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/image"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	rwfsOS "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

var regexDateTag = regexp.MustCompile(`^.*-(\d{4})(\d{2})(\d{2})$`)

var sbomCacheDir = filepath.Join(xdg.CacheHome, "wolfictl", "advisory", "sboms")

var styleBold = lipgloss.NewStyle().Bold(true)

func AdvisoryImage() *cobra.Command {
	var outputJSON bool
	var wolfiDirPath string

	cmd := &cobra.Command{
		Use:           "image <image-ref>",
		Short:         "Get advisory information for a container image",
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// get image ref
			input := args[0]

			imageHistory, err := assembleImageHistory(input)
			if err != nil {
				return fmt.Errorf("unable to assemble image history for image %q: %w", input, err)
			}

			diffHistory, err := diffImageHistory(*imageHistory)
			if err != nil {
				return fmt.Errorf("unable to compute diffs for image history %q: %w", input, err)
			}

			fsys := rwfsOS.DirFS(wolfiDirPath)
			index, err := configs.NewIndex(fsys)
			if err != nil {
				return err
			}

			versionDiffsWithAdvisories := lo.Map(diffHistory.VersionDiffs, addFixedAdvisoriesToVersionDiffs(index))
			diffHistory.VersionDiffs = versionDiffsWithAdvisories

			if outputJSON {
				err := json.NewEncoder(os.Stdout).Encode(diffHistory)
				if err != nil {
					return fmt.Errorf("unable to write diff history output: %w", err)
				}
				return nil
			}

			fmt.Println(pretty(input, *diffHistory))

			return nil
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("unable to get the current working directory: %w", err)
		return nil
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "output the analysis as JSON")
	cmd.Flags().StringVarP(&wolfiDirPath, "wolfi-dir", "d", cwd, "path to local clone of Wolfi repo")

	return cmd
}

func pretty(imageRef string, diffHistory image.DiffHistory) string {
	imageVersionPrefix := strings.Repeat(" ", 2)
	packageDiffPrefix := strings.Repeat(" ", 4) + "└─ "
	fixedAdvisoriesPrefix := strings.Repeat(" ", 8) + "└─ "

	result := imageRef + "\n"

	for _, d := range diffHistory.VersionDiffs {
		if !d.HasPackageDiffs() {
			continue
		}

		result += fmt.Sprintf("%s%s\n", imageVersionPrefix, d.ToImage)

		if pd := d.PackagesAdded; len(pd) > 0 {
			items := lo.Map(pd, func(p image.PackageDiff, _ int) string {
				return fmt.Sprintf("%sadds %s", packageDiffPrefix, p.Name)
			})

			result += fmt.Sprintf("%s\n", strings.Join(items, "\n"))
		}

		if pd := d.PackagesUpgraded; len(pd) > 0 {
			items := lo.Map(pd, func(p image.PackageDiff, _ int) string {
				packageLine := fmt.Sprintf("%supgrades %s to %s (from %s)\n", packageDiffPrefix, p.Name, p.ToVersion, p.FromVersion)

				fixedAdvisoryLines := lo.Map(p.FixedAdvisories, func(adv image.FixedAdvisory, _ int) string {
					line := fmt.Sprintf("%sfixes %s", fixedAdvisoriesPrefix, adv.VulnerabilityID)

					if adv.FixedVersion != p.ToVersion {
						line += fmt.Sprintf(" (via %s)", adv.FixedVersion)
					}

					line = styleBold.Render(line)

					line += "\n"

					return line
				})

				return strings.Join(append([]string{packageLine}, fixedAdvisoryLines...), "")
			})

			result += strings.Join(items, "")
		}

		if pd := d.PackagesDowngraded; len(pd) > 0 {
			items := lo.Map(pd, func(p image.PackageDiff, _ int) string {
				return fmt.Sprintf("%sdowngrades %s to %s (from %s)", packageDiffPrefix, p.Name, p.ToVersion, p.FromVersion)
			})

			result += fmt.Sprintf("%s\n", strings.Join(items, "\n"))
		}

		if pd := d.PackagesRemoved; len(pd) > 0 {
			items := lo.Map(pd, func(p image.PackageDiff, _ int) string {
				return fmt.Sprintf("%sremoves %s", packageDiffPrefix, p.Name)
			})

			result += fmt.Sprintf("%s\n", strings.Join(items, "\n"))
		}
	}

	return result
}

func addFixedAdvisoriesToVersionDiffs(index *configs.Index) func(image.VersionDiff, int) image.VersionDiff {
	return func(v image.VersionDiff, _ int) image.VersionDiff {
		upgradedPackagesWithAdvisories := lo.Map(v.PackagesUpgraded, addFixedAdvisoriesToPackageUpgrades(index))
		v.PackagesUpgraded = upgradedPackagesWithAdvisories
		return v
	}
}

func addFixedAdvisoriesToPackageUpgrades(index *configs.Index) func(image.PackageDiff, int) image.PackageDiff {
	return func(p image.PackageDiff, _ int) image.PackageDiff {
		name := p.Name
		config, err := index.Select().WherePackageOrSubpackageName(name).GetConfig()
		if err != nil {
			// TODO: find better solution to erroring from lo.Map
			panic(fmt.Errorf("unable to find package configuration for %q: %w", name, err))
		}

		for vulnID, advisoryContents := range config.Advisories {
			if len(advisoryContents) == 0 {
				continue
			}

			lastEntry := advisoryContents[len(advisoryContents)-1]
			if lastEntry.Status != vex.StatusFixed {
				continue
			}

			fixedVersion, err := versions.NewVersion(lastEntry.FixedVersion)
			if err != nil {
				// TODO: solve for this
				continue
			}

			fromVersion, err := versions.NewVersion(p.FromVersion)
			if err != nil {
				// TODO: solve for this
				continue
			}

			toVersion, err := versions.NewVersion(p.ToVersion)
			if err != nil {
				// TODO: solve for this
				continue
			}

			if fixedVersion.GreaterThan(fromVersion) && fixedVersion.LessThanOrEqual(toVersion) {
				p.FixedAdvisories = append(p.FixedAdvisories, image.FixedAdvisory{
					VulnerabilityID: vulnID,
					FixedVersion:    lastEntry.FixedVersion,
				})
			}
		}

		return p
	}
}

func diffImageHistory(history image.History) (*image.DiffHistory, error) {
	sort.Sort(image.ByBuildDateAsc(history.Versions))

	var versionDiffs []image.VersionDiff
	for i, current := range history.Versions {
		if i == 0 {
			continue
		}

		prior := history.Versions[i-1]

		diff := computeImageVersionDiff(current, prior)
		versionDiffs = append(versionDiffs, diff)
	}

	diffHistory := image.DiffHistory{
		VersionDiffs: versionDiffs,
	}

	return &diffHistory, nil
}

func computeImageVersionDiff(current, prior image.Version) image.VersionDiff {
	diff := newDiffTarget(current.Packages, prior.Packages)

	versionDiff := image.VersionDiff{
		FromImage:          prior.Identifier,
		ToImage:            current.Identifier,
		PackagesAdded:      computePackagesAdded(diff),
		PackagesUpgraded:   computePackagesUpgraded(diff),
		PackagesDowngraded: computePackagesDowngraded(diff),
		PackagesRemoved:    computePackagesRemoved(diff),
	}

	return versionDiff
}

func assembleImageHistory(imageReference string) (*image.History, error) {
	ref, err := name.ParseReference(imageReference)
	if err != nil {
		return nil, err
	}

	specifiedTag := ref.Identifier()
	log.Printf("specified tag %q", specifiedTag)

	// TODO: handle :latest, no tag

	// get history of digests
	repository := ref.Context()

	log.Printf("looking up tags for image %q", repository)
	tags, err := remote.List(repository)
	if err != nil {
		return nil, fmt.Errorf("unable to get tags for image repository %q: %w", repository, err)
	}

	relevantTags := lo.Filter(tags, func(tag string, _ int) bool {
		return strings.HasPrefix(fmt.Sprintf("%s:%s", repository, tag), imageReference)
	})

	dateTags := lo.Filter(relevantTags, func(currentTag string, _ int) bool {
		parts := regexDateTag.FindStringSubmatch(currentTag)
		if len(parts) < 4 {
			return false
		}

		if year := parts[1]; year == "2022" {
			return false
		}

		dateString := strings.Join(parts[1:4], "")

		expectedTag := fmt.Sprintf("%s-%s", specifiedTag, dateString)
		return currentTag == expectedTag
	})

	log.Printf("found %d relevant tag(s) for assembling image history", len(dateTags))

	var imageVersions []image.Version

	for _, tag := range dateTags {
		tagRef := fmt.Sprintf("%s:%s", repository, tag)

		sf := newSbomFetcher(sbomCacheDir, "linux/amd64")
		sbom, err := sf.fetch(tagRef)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch SBOM for %q: %w", tagRef, err)
		}

		wolfiSPDXPackages := lo.Filter(sbom.Packages, isWolfiPackage)
		imagePackages := lo.Map(wolfiSPDXPackages, spdxPackageToImagePackage)

		buildDate, err := calculateBuildDateFromTag(tag)
		if err != nil {
			return nil, err
		}

		imageVersion := image.Version{
			Identifier: image.Identifier{
				Repository: repository.String(),
				Tag:        tag,
			},
			BuildDate: buildDate,
			Packages:  imagePackages,
		}

		imageVersions = append(imageVersions, imageVersion)
	}

	history := image.History{
		ImageTagBase: imageReference,
		Versions:     imageVersions,
	}

	return &history, nil
}

func calculateBuildDateFromTag(tag string) (time.Time, error) {
	dateComponents := regexDateTag.FindStringSubmatch(tag)
	if len(dateComponents) < 4 {
		return time.Time{}, fmt.Errorf("unable to parse date for image tag %q", tag)
	}

	year, _ := strconv.Atoi(dateComponents[1])
	month, _ := strconv.Atoi(dateComponents[2])
	day, _ := strconv.Atoi(dateComponents[3])

	buildDate := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return buildDate, nil
}

func spdxPackageToImagePackage(p *v2_3.Package, _ int) image.Package {
	// assuming p != nil for now

	return image.Package{
		Name:    p.PackageName,
		Version: p.PackageVersion,
		PURL:    getPURLFromSPDXPackage(*p),
	}
}

type sbomFetcher struct {
	localCacheDir string
	platform      string
}

func newSbomFetcher(localCacheDir string, platform string) sbomFetcher {
	return sbomFetcher{localCacheDir: localCacheDir, platform: platform}
}

func (sf sbomFetcher) fetch(imageTag string) (*v2_3.Document, error) {
	// Try the cache first
	sbomBytes, err := sf.fetchFromCache(imageTag)
	if err != nil {
		if !errors.Is(err, errSBOMNotFoundInCache) {
			return nil, err
		}
	}

	// Then try retrieving it using Cosign
	if sbomBytes == nil {
		sbomBytes, err = sf.fetchWithCosign(imageTag)
		if err != nil {
			return nil, err
		}

		err = os.MkdirAll(sf.localCacheDir, 0755)
		if err != nil {
			return nil, err
		}

		// Success! Also, write it to the cache for next time!
		cacheFileName := determineSBOMCacheFileName(imageTag)
		err = os.WriteFile(filepath.Join(sf.localCacheDir, cacheFileName), sbomBytes, 0600)
		if err != nil {
			return nil, fmt.Errorf("unable to cache SBOM for %q: %w", imageTag, err)
		}
	}

	doc := new(v2_3.Document)
	err = json.Unmarshal(sbomBytes, doc)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal SBOM: %w", err)
	}

	return doc, nil
}

var errSBOMNotFoundInCache = errors.New("SBOM not found in the local cache")

func determineSBOMCacheFileName(imageTag string) string {
	r := strings.NewReplacer("/", "__", ":", "__")
	cacheFileName := r.Replace(imageTag) + ".spdx.json"
	return cacheFileName
}

func (sf sbomFetcher) fetchFromCache(imageTag string) ([]byte, error) {
	cacheFileName := determineSBOMCacheFileName(imageTag)
	cacheFilePath := filepath.Join(sf.localCacheDir, cacheFileName)
	b, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errSBOMNotFoundInCache
		}

		return nil, fmt.Errorf("unable to use cache to retrieve SBOM for %s: %w", imageTag, err)
	}

	return b, nil
}

func (sf sbomFetcher) fetchWithCosign(imageTag string) ([]byte, error) {
	cmd := exec.Command(
		"cosign",
		"download",
		"sbom",
		fmt.Sprintf("--platform=%s", sf.platform),
		imageTag,
	)
	sbomBuf := new(bytes.Buffer)
	cmd.Stdout = sbomBuf
	errorBuf := new(bytes.Buffer)
	cmd.Stderr = errorBuf

	log.Printf("fetching SBOM for %q", imageTag)

	err := cmd.Run()
	if err != nil {
		_, _ = errorBuf.WriteTo(os.Stderr)
		return nil, fmt.Errorf("error executing cosign command %q: %w", cmd, err)
	}

	return sbomBuf.Bytes(), nil
}

func isWolfiPackage(p *v2_3.Package, _ int) bool {
	if p == nil {
		return false
	}

	purl := getPURLFromSPDXPackage(*p)

	return strings.HasPrefix(purl, "pkg:apk/wolfi/")
}

func getPURLFromSPDXPackage(p v2_3.Package) string {
	purlRefs := lo.Filter(p.PackageExternalReferences, func(extRef *v2_3.PackageExternalReference, _ int) bool {
		if extRef == nil {
			return false
		}

		return extRef.RefType == "purl"
	})

	if len(purlRefs) == 0 {
		return ""
	}

	purl := purlRefs[0].Locator
	return purl
}

func packageByName(p image.Package) (string, image.Package) {
	return p.Name, p
}

func packageToName(p image.Package, _ int) string {
	return p.Name
}

func sortedPackagesFromMap(in map[string]image.Package) []image.Package {
	packages := lo.Values(in)
	sort.Sort(image.ByPackageName(packages))
	return packages
}

type diffTarget struct {
	priorPackageNames, currentPackageNames []string
	priorPackages, currentPackages         map[string]image.Package
}

func newDiffTarget(current, prior []image.Package) diffTarget {
	return diffTarget{
		priorPackages:       lo.Associate(prior, packageByName),
		priorPackageNames:   lo.Map(prior, packageToName),
		currentPackages:     lo.Associate(current, packageByName),
		currentPackageNames: lo.Map(current, packageToName),
	}
}

func computePackagesAdded(dt diffTarget) []image.PackageDiff {
	addedNames := lo.Without(dt.currentPackageNames, dt.priorPackageNames...)
	addedMap := lo.PickByKeys(dt.currentPackages, addedNames)
	added := sortedPackagesFromMap(addedMap)

	return lo.Map(added, func(p image.Package, _ int) image.PackageDiff {
		return image.PackageDiff{
			Name:        p.Name,
			FromVersion: "",
			ToVersion:   p.Version,
		}
	})
}

func computePackagesRemoved(dt diffTarget) []image.PackageDiff {
	removedNames := lo.Without(dt.priorPackageNames, dt.currentPackageNames...)
	removedMap := lo.PickByKeys(dt.priorPackages, removedNames)
	removed := sortedPackagesFromMap(removedMap)

	return lo.Map(removed, func(p image.Package, _ int) image.PackageDiff {
		return image.PackageDiff{
			Name:        p.Name,
			FromVersion: p.Version,
			ToVersion:   "",
		}
	})
}

func computePackagesUpgraded(dt diffTarget) []image.PackageDiff {
	return lo.Filter(computePackagesInBothRegardlessOfVersion(dt), func(diff image.PackageDiff, _ int) bool {
		return comparePackageVersions(diff.FromVersion, diff.ToVersion) < 0
	})
}

func computePackagesDowngraded(dt diffTarget) []image.PackageDiff {
	return lo.Filter(computePackagesInBothRegardlessOfVersion(dt), func(diff image.PackageDiff, _ int) bool {
		return comparePackageVersions(diff.FromVersion, diff.ToVersion) > 0
	})
}

func computePackagesInBothRegardlessOfVersion(dt diffTarget) []image.PackageDiff {
	keptNames := lo.Intersect(dt.priorPackageNames, dt.currentPackageNames)
	keptFromPriorMap := lo.PickByKeys(dt.priorPackages, keptNames)
	keptInCurrentMap := lo.PickByKeys(dt.currentPackages, keptNames)
	keptInCurrent := sortedPackagesFromMap(keptInCurrentMap)

	return lo.Map(keptInCurrent, func(p image.Package, _ int) image.PackageDiff {
		return image.PackageDiff{
			Name:        p.Name,
			FromVersion: keptFromPriorMap[p.Name].Version,
			ToVersion:   p.Version,
		}
	})
}

func comparePackageVersions(v1, v2 string) int {
	version1, err := versions.NewVersion(v1)
	if err != nil {
		log.Printf("unable to compare package versions that include version %q: %s", v1, err.Error())
		return 0
	}

	version2, err := versions.NewVersion(v2)
	if err != nil {
		log.Printf("unable to compare package versions that include version %q: %s", v2, err.Error())
		return 0
	}

	return version1.Compare(version2)
}
