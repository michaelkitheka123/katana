package siegeengine

import (
	"fmt"
	"os"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/tools"
)

const (
	validationTimeoutSecs = 120
	maxOutputChars        = 2048

	outputValidationTimeout     = "VALIDATION_TIMEOUT"
	outputValidationSkipped     = "VALIDATION_SKIPPED_DESTRUCTIVE"
)

// destructiveMethods lists HTTP methods that can cause state-mutating / destructive side effects.
var destructiveMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

// ValidatePoC attempts to execute a PoC and records the outcome on the poc struct.
//
// Behaviour:
//   - POST/PUT/PATCH/DELETE endpoints are skipped when allowDestructive is false;
//     validated is set to false and validationOutput to VALIDATION_SKIPPED_DESTRUCTIVE.
//   - curl_command PoCs are executed via the shared tool executor.
//   - python_script PoCs are written to a temp file and executed with python3.
//   - On timeout (exit code -1 or context deadline): validated=false, output=VALIDATION_TIMEOUT.
//   - On exit code 0: validated=true, output = first 2048 chars of stdout.
//   - On any other exit code: validated=false, output = first 2048 chars of stderr (or stdout).
func ValidatePoC(poc *shared.ProofOfConcept, endpoint shared.DiscoveredEndpoint, allowDestructive bool) error {
	// Guard: skip destructive endpoints unless explicitly permitted
	if !allowDestructive && destructiveMethods[strings.ToUpper(endpoint.Method)] {
		poc.Validated = false
		poc.ValidationOutput = outputValidationSkipped
		return nil
	}

	switch poc.Type {
	case shared.PoCTypeCurl:
		return validateCurl(poc)
	case shared.PoCTypePython:
		return validatePython(poc)
	default:
		// Unsupported PoC types cannot be auto-validated
		poc.Validated = false
		poc.ValidationOutput = fmt.Sprintf("VALIDATION_UNSUPPORTED_TYPE: %s", poc.Type)
		return nil
	}
}

// validateCurl executes a curl_command PoC using the shared tool executor.
func validateCurl(poc *shared.ProofOfConcept) error {
	// Split the stored curl command into individual arguments.
	// The content is expected to be a full curl invocation, e.g.:
	//   curl -s -o /dev/null -w "%{http_code}" https://example.com/vuln?id=1'
	args := parseCurlArgs(poc.Content)

	stdout, stderr, exitCode, err := tools.Execute("curl", args, validationTimeoutSecs)

	return applyResult(poc, stdout, stderr, exitCode, err)
}

// validatePython writes the python_script content to a temp file and executes it.
func validatePython(poc *shared.ProofOfConcept) error {
	// Extract Python code from markdown code fence if present
	// LLM responses may include: ```python\ncode\n```
	pythonCode := extractPythonCode(poc.Content)

	// Write script to a temporary file
	tmpFile, err := os.CreateTemp("", "templar-poc-*.py")
	if err != nil {
		poc.Validated = false
		poc.ValidationOutput = fmt.Sprintf("VALIDATION_ERROR: failed to create temp file: %v", err)
		return nil //nolint:nilerr // surfaced via poc fields, not error return
	}
	defer os.Remove(tmpFile.Name())

	if _, writeErr := tmpFile.WriteString(pythonCode); writeErr != nil {
		tmpFile.Close()
		poc.Validated = false
		poc.ValidationOutput = fmt.Sprintf("VALIDATION_ERROR: failed to write script: %v", writeErr)
		return nil //nolint:nilerr
	}
	tmpFile.Close()

	stdout, stderr, exitCode, err := tools.Execute("python3", []string{tmpFile.Name()}, validationTimeoutSecs)

	return applyResult(poc, stdout, stderr, exitCode, err)
}

// extractPythonCode removes markdown code fence wrappers from LLM-generated Python code.
// Handles: ```python\ncode\n``` or ```\ncode\n```
func extractPythonCode(content string) string {
	content = strings.TrimSpace(content)

	// Remove opening fence: ```python or ```
	if strings.HasPrefix(content, "```python") {
		content = strings.TrimPrefix(content, "```python")
	} else if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}

	// Remove closing fence: ```
	if strings.HasSuffix(content, "```") {
		content = strings.TrimSuffix(content, "```")
	}

	// Trim any leading/trailing whitespace after removing fences
	return strings.TrimSpace(content)
}

// applyResult writes the execution outcome back into the poc struct.
func applyResult(poc *shared.ProofOfConcept, stdout, stderr string, exitCode int, execErr error) error {
	// Timeout is signalled by exit code -1 set in executeOnce when DeadlineExceeded
	if exitCode == -1 || (execErr != nil && strings.Contains(execErr.Error(), "deadline exceeded")) {
		poc.Validated = false
		poc.ValidationOutput = outputValidationTimeout
		return nil
	}

	if exitCode == 0 {
		poc.Validated = true
		poc.ValidationOutput = truncate(stdout, maxOutputChars)
		return nil
	}

	// Non-zero exit — capture error output
	poc.Validated = false
	errOutput := stderr
	if errOutput == "" {
		errOutput = stdout
	}
	poc.ValidationOutput = truncate(errOutput, maxOutputChars)
	return nil
}

// parseCurlArgs splits a curl command string into argument tokens, stripping the
// leading "curl" binary name if present.
func parseCurlArgs(content string) []string {
	content = strings.TrimSpace(content)

	// Remove leading "curl " if the user stored the full command including the binary
	if strings.HasPrefix(strings.ToLower(content), "curl ") {
		content = content[5:]
	}

	// Naive whitespace split — sufficient for machine-generated PoC content.
	// A more robust shell-aware tokeniser would be needed for hand-crafted PoCs
	// with quoted strings containing spaces.
	var args []string
	for _, token := range strings.Fields(content) {
		args = append(args, token)
	}
	return args
}

// truncate returns at most n characters from s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
