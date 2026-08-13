package crusadeplanner

import (
	"strings"

	"github.com/templar-framework/templar/internal/shared"
)

// AttackGraphNode wraps a vulnerability with inferred preconditions and postconditions.
type AttackGraphNode struct {
	Vulnerability  shared.Vulnerability
	Preconditions  []string
	Postconditions []string
}

// AttackGraph is a directed graph where nodes are vulnerabilities and edges
// represent chaining opportunities (one vuln's postcondition enables another's
// precondition).
type AttackGraph struct {
	Nodes []*AttackGraphNode
	// Edges maps from a node to the list of nodes it enables.
	Edges map[*AttackGraphNode][]*AttackGraphNode
}

// NewAttackGraph creates an AttackGraph and populates nodes from the given
// vulnerabilities, filtering to only those with Status "confirmed" or
// "poc_available". Edges are not yet added; call BuildGraph for a fully
// connected graph.
func NewAttackGraph(vulns []shared.Vulnerability) *AttackGraph {
	g := &AttackGraph{
		Edges: make(map[*AttackGraphNode][]*AttackGraphNode),
	}

	for _, v := range vulns {
		if v.Status != "confirmed" && v.Status != "poc_available" {
			continue
		}
		node := &AttackGraphNode{
			Vulnerability:  v,
			Preconditions:  inferPreconditions(v),
			Postconditions: inferPostconditions(v),
		}
		g.Nodes = append(g.Nodes, node)
	}

	return g
}

// AddEdge adds a directed edge from → to if from's postconditions satisfy
// to's preconditions.
func (g *AttackGraph) AddEdge(from, to *AttackGraphNode) {
	if postconditionSatisfies(from, to.Preconditions) {
		g.Edges[from] = append(g.Edges[from], to)
	}
}

// postconditionSatisfies returns true if any of from's postconditions exactly
// matches a target precondition, or if the keyword overlap between the two
// sets is at least 50%.
func postconditionSatisfies(node *AttackGraphNode, targetPreconditions []string) bool {
	if len(targetPreconditions) == 0 {
		return false
	}

	// Exact string match first.
	for _, post := range node.Postconditions {
		for _, pre := range targetPreconditions {
			if post == pre {
				return true
			}
		}
	}

	// Keyword overlap scoring: count how many postconditions appear in
	// targetPreconditions (or vice-versa) and compare against the smaller set.
	postSet := make(map[string]struct{}, len(node.Postconditions))
	for _, p := range node.Postconditions {
		for _, kw := range tokenize(p) {
			postSet[kw] = struct{}{}
		}
	}

	preSet := make(map[string]struct{}, len(targetPreconditions))
	for _, p := range targetPreconditions {
		for _, kw := range tokenize(p) {
			preSet[kw] = struct{}{}
		}
	}

	overlap := 0
	for kw := range postSet {
		if _, ok := preSet[kw]; ok {
			overlap++
		}
	}

	smaller := len(postSet)
	if len(preSet) < smaller {
		smaller = len(preSet)
	}
	if smaller == 0 {
		return false
	}

	return float64(overlap)/float64(smaller) >= 0.5
}

// tokenize splits a condition string on underscores and spaces so that
// compound terms like "database_access" contribute individual keywords.
func tokenize(s string) []string {
	s = strings.ReplaceAll(s, "_", " ")
	parts := strings.Fields(s)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// inferPreconditions returns a rule-based list of preconditions for a
// vulnerability based on its VulnType.
func inferPreconditions(vuln shared.Vulnerability) []string {
	switch vuln.Type {
	case shared.VulnTypeSSRF:
		return []string{"network_access", "url_parameter"}
	case shared.VulnTypeRCE:
		return []string{"code_execution", "file_upload", "command_injection"}
	case shared.VulnTypeSQLi:
		return []string{"database_access", "injectable_parameter"}
	case shared.VulnTypeXSS:
		return []string{"reflected_input", "stored_input"}
	case shared.VulnTypeIDOR:
		return []string{"authenticated_session", "object_reference"}
	default:
		return []string{"web_access"}
	}
}

// inferPostconditions returns a rule-based list of postconditions for a
// vulnerability based on its VulnType.
func inferPostconditions(vuln shared.Vulnerability) []string {
	switch vuln.Type {
	case shared.VulnTypeSQLi:
		return []string{"database_access", "data_exfiltration", "authentication_bypass"}
	case shared.VulnTypeRCE:
		return []string{"code_execution", "full_system_access", "data_exfiltration"}
	case shared.VulnTypeSSRF:
		return []string{"internal_network_access", "metadata_access"}
	case shared.VulnTypeXSS:
		return []string{"session_theft", "credential_theft", "dom_manipulation"}
	case shared.VulnTypeIDOR:
		return []string{"unauthorized_data_access", "privilege_escalation"}
	default:
		return []string{"information_disclosure"}
	}
}

// BuildGraph constructs a fully connected AttackGraph: it creates all nodes
// from confirmed/poc_available vulnerabilities and then adds every valid
// directed edge between them.
func BuildGraph(vulns []shared.Vulnerability) *AttackGraph {
	g := NewAttackGraph(vulns)

	for _, from := range g.Nodes {
		for _, to := range g.Nodes {
			if from == to {
				continue
			}
			g.AddEdge(from, to)
		}
	}

	return g
}
