package types

import (
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

type (
	// TargetType represents the type of target
	TargetType string

	// LangType is an alias of TargetType for programming languages
	LangType = TargetType
)

const (
	Bundler       LangType = "bundler"
	GemSpec       LangType = "gemspec"
	Cargo         LangType = "cargo"
	Composer      LangType = "composer"
	Npm           LangType = "npm"
	NuGet         LangType = "nuget"
	DotNetCore    LangType = "dotnet-core"
	PackagesProps LangType = "packages-props"
	Pip           LangType = "pip"
	Pipenv        LangType = "pipenv"
	Poetry        LangType = "poetry"
	CondaPkg      LangType = "conda-pkg"
	CondaEnv      LangType = "conda-environment"
	PythonPkg     LangType = "python-pkg"
	NodePkg       LangType = "node-pkg"
	Yarn          LangType = "yarn"
	Pnpm          LangType = "pnpm"
	Jar           LangType = "jar"
	Pom           LangType = "pom"
	Gradle        LangType = "gradle"
	GoBinary      LangType = "gobinary"
	GoModule      LangType = "gomod"
	JavaScript    LangType = "javascript"
	RustBinary    LangType = "rustbinary"
	Conan         LangType = "conan"
	Cocoapods     LangType = "cocoapods"
	Swift         LangType = "swift"
	Pub           LangType = "pub"
	Hex           LangType = "hex"
	Bitnami       LangType = "bitnami"

	K8sUpstream LangType = "kubernetes"
	EKS         LangType = "eks" // Amazon Elastic Kubernetes Service
	GKE         LangType = "gke" // Google Kubernetes Engine
	AKS         LangType = "aks" // Azure Kubernetes Service
	RKE         LangType = "rke" // Rancher Kubernetes Engine
	OCP         LangType = "ocp" // Red Hat OpenShift Container Platform
)

type Library struct {
	ID                 string `json:",omitempty"`
	Name               string
	Version            string
	Dev                bool
	Indirect           bool          `json:",omitempty"`
	License            string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:",omitempty"`
	Locations          []Location    `json:",omitempty"`
	FilePath           string        `json:",omitempty"` // Required to show nested jars
}

type Libraries []Library

func (libs Libraries) Len() int { return len(libs) }
func (libs Libraries) Less(i, j int) bool {
	if libs[i].ID != libs[j].ID { // ID could be empty
		return libs[i].ID < libs[j].ID
	} else if libs[i].Name != libs[j].Name { // Name could be the same
		return libs[i].Name < libs[j].Name
	}
	return libs[i].Version < libs[j].Version
}
func (libs Libraries) Swap(i, j int) { libs[i], libs[j] = libs[j], libs[i] }

// Location in lock file
type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

type ExternalRef struct {
	Type RefType
	URL  string
}

type Dependency struct {
	ID        string
	Root      bool
	DependsOn []string
}

type Dependencies []Dependency

func (deps Dependencies) Len() int { return len(deps) }
func (deps Dependencies) Less(i, j int) bool {
	return deps[i].ID < deps[j].ID
}
func (deps Dependencies) Swap(i, j int) { deps[i], deps[j] = deps[j], deps[i] }

type Parser interface {
	// Parse parses the dependency file
	Parse(r dio.ReadSeekerAt) ([]Library, []Dependency, error)
}

type RefType string

const (
	RefWebsite      RefType = "website"
	RefLicense      RefType = "license"
	RefVCS          RefType = "vcs"
	RefIssueTracker RefType = "issue-tracker"
	RefOther        RefType = "other"
)
