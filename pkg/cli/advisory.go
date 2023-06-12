package cli

import (
	"fmt"
	"os"
	"sort"

	"chainguard.dev/melange/pkg/build"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

const (
	envVarNameForDistroDir     = "WOLFICTL_DISTRO_REPO_DIR"
	envVarNameForAdvisoriesDir = "WOLFICTL_ADVISORIES_REPO_DIR"
)

func Advisory() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "advisory",
		Aliases:       []string{"adv"},
		SilenceErrors: true,
		Short:         "Utilities for viewing and modifying Wolfi advisory data",
	}

	cmd.AddCommand(AdvisoryList())
	cmd.AddCommand(AdvisoryCreate())
	cmd.AddCommand(AdvisoryUpdate())
	cmd.AddCommand(AdvisorySyncSecfixes())
	cmd.AddCommand(AdvisoryDiscover())
	cmd.AddCommand(AdvisoryDB())

	return cmd
}

func resolveDistroDir(cliFlagValue string) string {
	if v := cliFlagValue; v != "" {
		return v
	}

	return os.Getenv(envVarNameForDistroDir)
}

func resolveAdvisoriesDir(cliFlagValue string) string {
	if v := cliFlagValue; v != "" {
		return v
	}

	if v := os.Getenv(envVarNameForAdvisoriesDir); v != "" {
		return v
	}

	return ""
}

func renderDetectedDistro(d distro.Distro) string {
	return styles.Secondary().Render("Auto-detected distro: ") + d.Name + "\n\n"
}

type advisoryRequestParams struct {
	packageName, vuln, status, action, impact, justification, timestamp, fixedVersion string

	// Deprecated: This flag is no longer used, and so this field is ignored.
	sync bool
}

func (p *advisoryRequestParams) addFlags(cmd *cobra.Command) {
	addPackageFlag(&p.packageName, cmd)
	addVulnFlag(&p.vuln, cmd)

	cmd.Flags().BoolVar(&p.sync, "sync", false, "synchronize secfixes data immediately after updating advisory")

	_ = cmd.Flags().MarkDeprecated("sync", "because 'secfixes' data is no longer used. This flag now has no effect, and it will be removed in an upcoming version.") //nolint:errcheck
}

func (p *advisoryRequestParams) advisoryRequest() (advisory.Request, error) {
	return advisory.Request{
		Package:       p.packageName,
		Vulnerability: p.vuln,
	}, nil
}

func addPackageFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "package", "p", "", "package name")
}

func addVulnFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "vuln", "V", "", "vulnerability ID for advisory")
}

func addDistroDirFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "distro-repo-dir", "d", "", fmt.Sprintf("directory containing the distro repository (can also be set with environment variable `%s`)", envVarNameForDistroDir))
}

func addAdvisoriesDirFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "advisories-repo-dir", "a", "", fmt.Sprintf("directory containing the advisories repository (can also be set with environment variable `%s`)", envVarNameForAdvisoriesDir))
}

func addNoPromptFlag(val *bool, cmd *cobra.Command) {
	cmd.Flags().BoolVar(val, "no-prompt", false, "do not prompt the user for input")
}

func addNoDistroDetectionFlag(val *bool, cmd *cobra.Command) {
	cmd.Flags().BoolVar(val, "no-distro-detection", false, "do not attempt to auto-detect the distro")
}

func newAllowedFixedVersionsFunc(apkindexes []*repository.ApkIndex, buildCfgs *configs.Index[build.Configuration]) func(packageName string) []string {
	return func(packageName string) []string {
		allowedVersionSet := make(map[string]struct{})

		// Get published versions using APKINDEX data.

		for _, apkindex := range apkindexes {
			for _, pkg := range apkindex.Packages {
				if pkg.Name == packageName {
					allowedVersionSet[pkg.Version] = struct{}{}
				}
			}
		}

		// Also ensure the currently defined version is included in the set, even if it's not been published yet.

		pkg := buildCfgs.Select().WhereName(packageName).Configurations()[0].Package
		currentVersion := fmt.Sprintf("%s-r%d", pkg.Version, pkg.Epoch)
		allowedVersionSet[currentVersion] = struct{}{}

		allowedVersions := lo.Keys(allowedVersionSet)
		sort.Sort(versions.ByLatestStrings(allowedVersions))

		return allowedVersions
	}
}
