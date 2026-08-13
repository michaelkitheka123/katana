// Package chronicle implements the report rendering engine for the Scribe Knight.
//
// Chronicle is responsible for retrieving all campaign artifacts from the Seneschal
// state store and rendering them into one or more output formats: PDF, HTML, Markdown,
// JSON, and SARIF. The package is structured in two layers:
//
//   - Data retrieval (retriever.go): fetches the full ArtifactBundle for a campaign
//     before any rendering begins, failing fast if required artifacts are unavailable.
//
//   - Rendering (forthcoming): transforms an ArtifactBundle into formatted report files
//     written to the operator-configured output directory.
//
// Chronicle is invoked by the Scribe after all preceding campaign phases
// (Preceptor → Hospitaller → Marshal → Chaplain) have reached a terminal state.
package chronicle
