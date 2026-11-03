package ctis

import "slices"

// Dependency is a software component (SBOM). Its identity is the versionless
// purl; the ecosystem is the purl type.
type Dependency struct {
	// Document-local reference. Never UUID-shaped.
	ID string `json:"id,omitempty"`

	// Component name (required) and version.
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`

	// Component type (CycloneDX component types, verbatim).
	Type DependencyType `json:"type,omitempty"`

	// Package URL.
	PURL string `json:"purl,omitempty"`

	// The producer's own id of the component (a CycloneDX bom-ref, an SPDX
	// element id).
	SourceID string `json:"source_id,omitempty"`

	// SPDX license ids or expressions.
	Licenses []string `json:"licenses,omitempty"`

	// Place in the dependency graph: root, direct, transitive.
	Relationship DependencyRelationship `json:"relationship,omitempty"`

	// Ids of the dependencies of this report this one depends on.
	DependsOn []string `json:"depends_on,omitempty"`

	// Where the component is declared (manifest, lock file).
	Locations []DependencyLocation `json:"locations,omitempty"`

	// The asset of this report the component was found in.
	AssetRef string `json:"asset_ref,omitempty"`

	// Opaque bag; no meaning.
	Properties Properties `json:"properties,omitempty"`

	// Namespaced producer data.
	Extensions Extensions `json:"extensions,omitempty"`
}

// DependencyLocation is a place in a file where a component is declared.
type DependencyLocation struct {
	Path        string `json:"path,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

// DependencyRelationship is the place of a component in the graph.
type DependencyRelationship string

// Dependency relationships.
const (
	DependencyRoot       DependencyRelationship = "root"
	DependencyDirect     DependencyRelationship = "direct"
	DependencyTransitive DependencyRelationship = "transitive"
)

// AllDependencyRelationships returns every dependency relationship.
func AllDependencyRelationships() []DependencyRelationship {
	return []DependencyRelationship{DependencyRoot, DependencyDirect, DependencyTransitive}
}

// IsValid reports whether r is a known relationship.
func (r DependencyRelationship) IsValid() bool {
	return slices.Contains(AllDependencyRelationships(), r)
}

// DependencyType is a CycloneDX component type, verbatim.
type DependencyType string

// Dependency types.
const (
	DependencyTypeApplication      DependencyType = "application"
	DependencyTypeFramework        DependencyType = "framework"
	DependencyTypeLibrary          DependencyType = "library"
	DependencyTypeContainer        DependencyType = "container"
	DependencyTypePlatform         DependencyType = "platform"
	DependencyTypeOperatingSystem  DependencyType = "operating-system"
	DependencyTypeDevice           DependencyType = "device"
	DependencyTypeDeviceDriver     DependencyType = "device-driver"
	DependencyTypeFirmware         DependencyType = "firmware"
	DependencyTypeFile             DependencyType = "file"
	DependencyTypeMachineLearning  DependencyType = "machine-learning-model"
	DependencyTypeData             DependencyType = "data"
	DependencyTypeCryptographicAst DependencyType = "cryptographic-asset"
)

// AllDependencyTypes returns every dependency type.
func AllDependencyTypes() []DependencyType {
	return []DependencyType{
		DependencyTypeApplication, DependencyTypeFramework, DependencyTypeLibrary, DependencyTypeContainer,
		DependencyTypePlatform, DependencyTypeOperatingSystem, DependencyTypeDevice, DependencyTypeDeviceDriver,
		DependencyTypeFirmware, DependencyTypeFile, DependencyTypeMachineLearning, DependencyTypeData,
		DependencyTypeCryptographicAst,
	}
}

// IsValid reports whether t is a known dependency type.
func (t DependencyType) IsValid() bool { return slices.Contains(AllDependencyTypes(), t) }
