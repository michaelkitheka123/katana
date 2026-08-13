package chronicle

import "encoding/json"

// RenderJSON serialises the full ArtifactBundle into a well-formed, indented JSON
// document. Every field of ArtifactBundle is included in the output. The resulting
// byte slice can be written directly to a .json report file.
func RenderJSON(bundle *ArtifactBundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", "  ")
}
