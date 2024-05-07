package csproj

import "encoding/xml"

type packageReference struct {
	XMLName           xml.Name `xml:"PackageReference"`
	Version           string   `xml:"Version,attr"`
	Include           string   `xml:"Include,attr"`
	PrivateAssetsTag  string   `xml:"PrivateAssets"`
	PrivateAssetsAttr string   `xml:"PrivateAssets,attr"`
	ExcludeAssetsTag  string   `xml:"ExcludeAssets"`
	ExcludeAssetsAttr string   `xml:"ExcludeAssets,attr"`
}

type csProject struct {
	XMLName  xml.Name           `xml:"Project"`
	Packages []packageReference `xml:"ItemGroup>PackageReference"`
}
