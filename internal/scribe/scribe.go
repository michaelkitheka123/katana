package scribe

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/templar-framework/templar/internal/scribe/chronicle"
	"github.com/templar-framework/templar/internal/seneschal"
)

// Scribe is the reporting coordinator. It retrieves all campaign artifacts from the
// Seneschal store and writes formatted report files to an output directory.
type Scribe struct {
	Store *seneschal.Store
}

// NewScribe creates a new Scribe bound to the given Seneschal store.
func NewScribe(store *seneschal.Store) *Scribe {
	return &Scribe{Store: store}
}

// validFormats lists the report formats the Scribe can render.
var validFormats = map[string]bool{
	"json":     true,
	"markdown": true,
	"html":     true,
	"pdf":      true,
	"sarif":    true,
}

// formatExt maps a format name to its file extension.
var formatExt = map[string]string{
	"json":     "json",
	"markdown": "md",
	"html":     "html",
	"pdf":      "pdf",
	"sarif":    "sarif.json",
}

// WriteChronicle generates reports for all requested formats and writes them to
// outputDir. Returns a map of format -> output file path for successfully written
// reports.
//
// The function fails immediately if artifact retrieval fails or if outputDir cannot
// be created or is not writable. Per-format render or write failures return a
// REPORT_WRITE_FAILED:<format> error. Unsupported formats are skipped with a log
// warning and do not cause an error.
func (s *Scribe) WriteChronicle(campaignID string, outputDir string, formats []string) (map[string]string, error) {
	// Step 1 — Retrieve all artifacts; fail fast on error.
	bundle, err := chronicle.RetrieveAllArtifacts(s.Store, campaignID)
	if err != nil {
		return nil, err
	}

	// Step 2 — Ensure outputDir exists and is writable.
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", outputDir)
	}
	// Verify writability with a probe file.
	probe := filepath.Join(outputDir, ".templar_write_probe")
	if err := os.WriteFile(probe, []byte{}, 0600); err != nil {
		return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", outputDir)
	}
	_ = os.Remove(probe)

	// Step 3 — Render and write each requested format.
	result := make(map[string]string)

	for _, format := range formats {
		if !validFormats[format] {
			log.Printf("UNSUPPORTED_FORMAT:%s", format)
			continue
		}

		ext := formatExt[format]
		outPath := filepath.Join(outputDir, fmt.Sprintf("%s.%s", campaignID, ext))

		var data []byte

		switch format {
		case "json":
			data, err = chronicle.RenderJSON(bundle)
			if err != nil {
				return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", format)
			}

		case "markdown":
			md, renderErr := chronicle.RenderMarkdown(bundle)
			if renderErr != nil {
				return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", format)
			}
			data = []byte(md)

		case "html":
			html, renderErr := chronicle.RenderHTML(bundle)
			if renderErr != nil {
				return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", format)
			}
			data = []byte(html)

		case "pdf":
			// No native PDF renderer is present; fall back to writing an HTML file
			// with a .pdf extension. Operators can post-process with wkhtmltopdf or
			// a similar tool.
			html, renderErr := chronicle.RenderHTML(bundle)
			if renderErr != nil {
				return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", format)
			}
			data = []byte(html)

		case "sarif":
			data, err = chronicle.RenderSARIF(bundle)
			if err != nil {
				return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", format)
			}
		}

		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return nil, fmt.Errorf("REPORT_WRITE_FAILED:%s", format)
		}

		result[format] = outPath
	}

	return result, nil
}
