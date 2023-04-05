package image

import (
	"fmt"
	"strings"
	"time"
)

type History struct {
	ImageTagBase string    `json:"imageTagBase"`
	Versions     []Version `json:"versions"`
}

type Version struct {
	Identifier Identifier `json:"identifier"`
	BuildDate  time.Time  `json:"buildDate"`
	Packages   []Package  `json:"packages"`
}

type ByBuildDateAsc []Version

func (by ByBuildDateAsc) Len() int {
	return len(by)
}

func (by ByBuildDateAsc) Less(i, j int) bool {
	return by[i].BuildDate.Before(by[j].BuildDate)
}

func (by ByBuildDateAsc) Swap(i, j int) {
	by[i], by[j] = by[j], by[i]
}

type Identifier struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

func (i Identifier) String() string {
	var tag, digest string

	if i.Tag != "" {
		tag = ":" + i.Tag
	}
	if i.Digest != "" {
		digest = "@" + i.Digest
	}

	return fmt.Sprintf("%s%s%s", i.Repository, tag, digest)
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type ByPackageName []Package

func (by ByPackageName) Len() int {
	return len(by)
}

func (by ByPackageName) Less(i, j int) bool {
	return strings.Compare(by[i].Name, by[j].Name) <= 0
}

func (by ByPackageName) Swap(i, j int) {
	by[i], by[j] = by[j], by[i]
}

type DiffHistory struct {
	VersionDiffs []VersionDiff `json:"versionDiffs"`
}

type VersionDiff struct {
	FromImage          Identifier    `json:"fromImage"`
	ToImage            Identifier    `json:"toImage"`
	PackagesAdded      []PackageDiff `json:"packagesAdded"`
	PackagesUpgraded   []PackageDiff `json:"packagesUpgraded"`
	PackagesDowngraded []PackageDiff `json:"packagesDowngraded"`
	PackagesRemoved    []PackageDiff `json:"packagesRemoved"`
}

func (d VersionDiff) HasPackageDiffs() bool {
	return len(d.PackagesAdded) > 0 ||
		len(d.PackagesUpgraded) > 0 ||
		len(d.PackagesDowngraded) > 0 ||
		len(d.PackagesRemoved) > 0
}

type PackageDiff struct {
	Name            string          `json:"name"`
	FromVersion     string          `json:"fromVersion,omitempty"`
	ToVersion       string          `json:"toVersion,omitempty"`
	FixedAdvisories []FixedAdvisory `json:"fixedAdvisories,omitempty"`
}

type FixedAdvisory struct {
	VulnerabilityID string `json:"vulnerabilityID"`
	FixedVersion    string `json:"fixedVersion"`
}
