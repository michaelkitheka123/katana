package chronicle

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// reportTemplate is the self-contained HTML template for the campaign report.
// All CSS is inlined so the file is portable with no external dependencies.
const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Templar Security Report — {{.CampaignID}}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    color: #1a1a2e;
    background: #f4f6fb;
  }
  .page { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
  header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
    color: #e2e8f0;
    padding: 36px 40px;
    border-radius: 8px;
    margin-bottom: 32px;
  }
  header h1 { font-size: 2rem; font-weight: 700; letter-spacing: 0.02em; }
  header .meta { margin-top: 8px; font-size: 0.85rem; opacity: 0.75; }
  section { background: #fff; border-radius: 8px; padding: 28px 32px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.07); }
  h2 { font-size: 1.25rem; font-weight: 700; color: #0f3460; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 20px; }
  h3 { font-size: 1rem; font-weight: 600; color: #16213e; margin: 16px 0 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { background: #f0f4ff; color: #0f3460; text-align: left; padding: 10px 12px; font-weight: 600; border-bottom: 2px solid #d0d9f0; }
  td { padding: 9px 12px; border-bottom: 1px solid #eef0f6; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:nth-child(even) td { background: #f8f9fd; }
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .badge-critical { background: #fde8e8; color: #9b1c1c; }
  .badge-high     { background: #fef3c7; color: #92400e; }
  .badge-medium   { background: #fff8e1; color: #78350f; }
  .badge-low      { background: #ecfdf5; color: #065f46; }
  .badge-info     { background: #e0f2fe; color: #075985; }
  .stat-grid { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .stat-card { flex: 1; min-width: 140px; background: #f0f4ff; border-radius: 6px; padding: 16px; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: 700; color: #0f3460; }
  .stat-card .label { font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px; }
  .evidence-block { background: #f8f9fd; border-left: 3px solid #6366f1; padding: 10px 14px; margin-top: 8px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; }
  .poc-block { background: #0f1724; color: #a8d8a8; padding: 14px 16px; border-radius: 6px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; margin-top: 8px; }
  .chain-step { display: flex; align-items: flex-start; gap: 12px; padding: 10px 0; border-bottom: 1px dashed #e2e8f0; }
  .chain-step:last-child { border-bottom: none; }
  .step-number { flex-shrink: 0; width: 28px; height: 28px; border-radius: 50%; background: #0f3460; color: #fff; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 700; }
  .warning-list { list-style: none; }
  .warning-list li { padding: 7px 10px; margin-bottom: 6px; border-radius: 4px; background: #fff8e1; border-left: 3px solid #f59e0b; font-size: 0.875rem; }
  .empty-state { text-align: center; color: #9ca3af; padding: 24px; font-style: italic; }
  code { font-family: monospace; font-size: 0.85em; background: #f3f4f6; padding: 1px 4px; border-radius: 3px; }
  footer { text-align: center; color: #9ca3af; font-size: 0.8rem; margin-top: 40px; padding: 16px 0; }
</style>
</head>
<body>
<div class="page">

<header>
  <h1>⚔ Templar Security Report</h1>
  <div class="meta">
    Campaign ID: <strong>{{.CampaignID}}</strong> &nbsp;|&nbsp;
    Generated: <strong>{{.GeneratedAt}}</strong>
  </div>
</header>

<!-- 1. Executive Summary -->
<section id="executive-summary">
  <h2>1. Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="value">{{.Stats.TotalVulns}}</div><div class="label">Total Vulnerabilities</div></div>
    <div class="stat-card"><div class="value">{{.Stats.Critical}}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="value">{{.Stats.High}}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="value">{{.Stats.Medium}}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="value">{{.Stats.Low}}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="value">{{.Stats.TotalChains}}</div><div class="label">Attack Chains</div></div>
    <div class="stat-card"><div class="value">{{.Stats.TotalPoCs}}</div><div class="label">Proof of Concepts</div></div>
  </div>

  {{if .DegradedPhases}}
  <h3>⚠ Operational Issues</h3>
  <ul class="warning-list">
    {{range .DegradedPhases}}<li>Phase <strong>{{.}}</strong> completed in a degraded state — results may be incomplete.</li>{{end}}
  </ul>
  {{end}}

  {{if .ScopeViolations}}
  <h3>🚫 Excluded Targets</h3>
  <ul class="warning-list">
    {{range .ScopeViolations}}<li><code>{{.}}</code> was blocked by the Scope Enforcer.</li>{{end}}
  </ul>
  {{end}}
</section>

<!-- 2. Attack Surface -->
<section id="attack-surface">
  <h2>2. Attack Surface</h2>

  <h3>Subdomains ({{len .AttackSurface.Subdomains}})</h3>
  {{if .AttackSurface.Subdomains}}
  <table>
    <thead><tr><th>Domain</th><th>IP</th><th>Sources</th></tr></thead>
    <tbody>
      {{range .AttackSurface.Subdomains}}
      <tr>
        <td><code>{{.Domain}}</code></td>
        <td>{{.IP}}</td>
        <td>{{join .Source ", "}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}<p class="empty-state">No subdomains discovered.</p>{{end}}

  <h3>Hosts ({{len .AttackSurface.Hosts}})</h3>
  {{if .AttackSurface.Hosts}}
  <table>
    <thead><tr><th>IP</th><th>Open Ports</th><th>Services</th></tr></thead>
    <tbody>
      {{range .AttackSurface.Hosts}}
      <tr>
        <td><code>{{.IP}}</code></td>
        <td>{{joinInts .OpenPorts ", "}}</td>
        <td>{{join .Services ", "}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}<p class="empty-state">No hosts discovered.</p>{{end}}

  <h3>Endpoints ({{len .AttackSurface.Endpoints}})</h3>
  {{if .AttackSurface.Endpoints}}
  <table>
    <thead><tr><th>Method</th><th>URL</th><th>Parameters</th></tr></thead>
    <tbody>
      {{range .AttackSurface.Endpoints}}
      <tr>
        <td><code>{{.Method}}</code></td>
        <td><code>{{.URL}}</code></td>
        <td>{{paramNames .Parameters}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}<p class="empty-state">No endpoints discovered.</p>{{end}}
</section>

<!-- 3. Vulnerabilities -->
<section id="vulnerabilities">
  <h2>3. Vulnerabilities</h2>
  {{if .Vulnerabilities}}
  {{range .Vulnerabilities}}
  <div style="margin-bottom:24px; border: 1px solid #e2e8f0; border-radius:6px; overflow:hidden;">
    <div style="background:#f0f4ff; padding:12px 16px; display:flex; align-items:center; gap:12px;">
      <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
      <strong>{{.Title}}</strong>
      <span style="margin-left:auto; font-size:0.8rem; color:#6b7280;">ID: <code>{{.ID}}</code> &nbsp; Type: <code>{{.Type}}</code> &nbsp; CVSS: <strong>{{printf "%.1f" .CVSSScore}}</strong></span>
    </div>
    <div style="padding:12px 16px;">
      <p style="color:#374151; margin-bottom:8px;">{{.Description}}</p>
      <p><strong>Endpoint:</strong> <code>{{.Endpoint.Method}} {{.Endpoint.URL}}</code></p>
      {{if .Evidence}}
      <h3>Evidence</h3>
      {{range .Evidence}}
      <div class="evidence-block"><strong>{{.Type}}</strong>{{if .MatchedTemplate}} [{{.MatchedTemplate}}]{{end}}
{{.Details}}</div>
      {{end}}
      {{end}}
    </div>
  </div>
  {{end}}
  {{else}}<p class="empty-state">No vulnerabilities found.</p>{{end}}
</section>

<!-- 4. Proof of Concepts -->
<section id="proof-of-concepts">
  <h2>4. Proof of Concepts</h2>
  {{if .PoCs}}
  {{range .PoCs}}
  <div style="margin-bottom:20px;">
    <h3>PoC <code>{{.ID}}</code> — <em>{{.Type}}</em> &nbsp; <span style="font-size:0.8rem; color:#6b7280;">Vuln: {{.VulnerabilityID}}</span>
      {{if .Validated}}&nbsp;<span class="badge badge-low">✓ Validated</span>{{end}}
    </h3>
    <div class="poc-block">{{.Content}}</div>
    {{if .ValidationOutput}}<div class="evidence-block" style="margin-top:6px;"><strong>Validation Output:</strong>
{{.ValidationOutput}}</div>{{end}}
  </div>
  {{end}}
  {{else}}<p class="empty-state">No proof-of-concept exploits generated.</p>{{end}}
</section>

<!-- 5. Attack Chains -->
<section id="attack-chains">
  <h2>5. Attack Chains</h2>
  {{if .AttackChains}}
  {{range .AttackChains}}
  <div style="margin-bottom:28px; border: 1px solid #e2e8f0; border-radius:6px; overflow:hidden;">
    <div style="background:#f0f4ff; padding:12px 16px;">
      <strong>Chain ID:</strong> <code>{{.ID}}</code> &nbsp;
      <strong>Combined CVSS:</strong> {{printf "%.1f" .CombinedCVSS}} &nbsp;
      <strong>Impact:</strong> <span class="badge {{severityClass .Impact.Level}}">{{.Impact.Level}}</span>
    </div>
    <div style="padding:12px 16px;">
      <p style="margin-bottom:12px; color:#374151;">{{.Impact.Description}}</p>
      {{range $i, $step := .Steps}}
      <div class="chain-step">
        <div class="step-number">{{inc $i}}</div>
        <div>
          <strong>{{$step.Vulnerability.Title}}</strong> (<code>{{$step.Vulnerability.Endpoint.URL}}</code>)
          {{if $step.Preconditions}}<div style="font-size:0.8rem; color:#6b7280; margin-top:4px;">Pre: {{join $step.Preconditions " → "}}</div>{{end}}
          {{if $step.Postconditions}}<div style="font-size:0.8rem; color:#6b7280;">Post: {{join $step.Postconditions " → "}}</div>{{end}}
        </div>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}
  {{else}}<p class="empty-state">No attack chains identified.</p>{{end}}
</section>

<footer>
  Generated by <strong>Templar</strong> v1.0.0 &nbsp;|&nbsp; {{.GeneratedAt}}
</footer>

</div>
</body>
</html>`

// reportData is the view model passed to the HTML template.
type reportData struct {
	CampaignID    string
	GeneratedAt   string
	Stats         reportStats
	AttackSurface interface{}
	Vulnerabilities interface{}
	PoCs          interface{}
	AttackChains  interface{}
	DegradedPhases  []string
	ScopeViolations []string
}

type reportStats struct {
	TotalVulns  int
	Critical    int
	High        int
	Medium      int
	Low         int
	Info        int
	TotalChains int
	TotalPoCs   int
}

// RenderHTML renders the ArtifactBundle as a complete, self-contained HTML page.
// All CSS is inlined; no external resources are referenced.
func RenderHTML(bundle *ArtifactBundle) (string, error) {
	if bundle == nil {
		return "", fmt.Errorf("chronicle: RenderHTML called with nil bundle")
	}

	stats := computeStats(bundle)

	funcMap := template.FuncMap{
		"join": func(s []string, sep string) string {
			return strings.Join(s, sep)
		},
		"joinInts": func(ints []int, sep string) string {
			parts := make([]string, len(ints))
			for i, v := range ints {
				parts[i] = fmt.Sprintf("%d", v)
			}
			return strings.Join(parts, sep)
		},
		"paramNames": func(params interface{}) string {
			type named interface{ GetName() string }
			// Use type assertion to shared.DiscoveredParameter slice.
			// We receive it as interface{} from the template data but the
			// concrete type is always []shared.DiscoveredParameter.
			type dp struct{ Name string }
			switch p := params.(type) {
			case []struct{ Name string }:
				names := make([]string, len(p))
				for i, v := range p {
					names[i] = v.Name
				}
				return strings.Join(names, ", ")
			default:
				return ""
			}
		},
		"severityClass": severityBadgeClass,
		"inc": func(i int) int { return i + 1 },
	}

	// We pass the bundle fields directly so the template can access the concrete
	// shared.* types (required for field access like .Domain, .IP, etc.).
	type templateData struct {
		CampaignID      string
		GeneratedAt     string
		Stats           reportStats
		AttackSurface   interface{}
		Vulnerabilities interface{}
		PoCs            interface{}
		AttackChains    interface{}
		DegradedPhases  []string
		ScopeViolations []string
	}

	data := templateData{
		CampaignID:      bundle.CampaignID,
		GeneratedAt:     time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Stats:           stats,
		AttackSurface:   bundle.AttackSurface,
		Vulnerabilities: bundle.Vulnerabilities,
		PoCs:            bundle.PoCs,
		AttackChains:    bundle.AttackChains,
		DegradedPhases:  bundle.DegradedPhases,
		ScopeViolations: bundle.ScopeViolations,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return "", fmt.Errorf("chronicle: failed to parse HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("chronicle: failed to execute HTML template: %w", err)
	}

	return buf.String(), nil
}

// computeStats counts vulnerability severities and totals for the summary panel.
func computeStats(bundle *ArtifactBundle) reportStats {
	s := reportStats{
		TotalVulns:  len(bundle.Vulnerabilities),
		TotalChains: len(bundle.AttackChains),
		TotalPoCs:   len(bundle.PoCs),
	}
	for _, v := range bundle.Vulnerabilities {
		switch strings.ToLower(v.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

// severityBadgeClass maps a severity string to a CSS badge class.
func severityBadgeClass(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "badge-critical"
	case "high":
		return "badge-high"
	case "medium":
		return "badge-medium"
	case "low":
		return "badge-low"
	default:
		return "badge-info"
	}
}
