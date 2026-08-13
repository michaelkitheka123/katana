package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

// MaxConcurrency is retained for compatibility with the rest of Templar.
// It is no longer mutated inside Execute(), because doing so from concurrent
// tool executions can introduce race conditions.
var MaxConcurrency = 10

// Execute runs an external tool and captures:
//   - stdout
//   - stderr
//   - exit code
//   - execution error
//
// The tool is attempted twice when the first attempt fails.
//
// Unlike the previous implementation, diagnostics from the first attempt are
// preserved in the audit log rather than silently being overwritten by the
// second attempt.
func Execute(
	toolName string,
	args []string,
	timeoutSecs int,
) (stdout, stderr string, exitCode int, err error) {

	// -------------------------------------------------------------------------
	// Validate arguments
	// -------------------------------------------------------------------------

	if strings.TrimSpace(toolName) == "" {
		return "", "", 127, fmt.Errorf("tool name is empty")
	}

	if timeoutSecs <= 0 {
		return "", "", 124, fmt.Errorf(
			"invalid timeout for %s: %d seconds",
			toolName,
			timeoutSecs,
		)
	}

	// -------------------------------------------------------------------------
	// Resolve the executable before attempting to run it.
	//
	// This gives us a useful error such as:
	//
	//     tool "nuclei" not found in PATH
	//
	// instead of the much less useful:
	//
	//     Tool nuclei failed twice
	// -------------------------------------------------------------------------

	resolvedTool, lookErr := exec.LookPath(toolName)
	if lookErr != nil {
		message := fmt.Sprintf(
			"Tool %q could not be resolved: %v; PATH=%s",
			toolName,
			lookErr,
			getPATH(),
		)

		logToolFailure(
			toolName,
			args,
			127,
			lookErr,
			"",
			message,
		)

		return "", "", 127, fmt.Errorf(
			"tool %q not found in PATH: %w",
			toolName,
			lookErr,
		)
	}

	// -------------------------------------------------------------------------
	// First attempt
	// -------------------------------------------------------------------------

	stdout, stderr, exitCode, err = executeOnce(
		resolvedTool,
		toolName,
		args,
		timeoutSecs,
	)

	if exitCode == 0 && err == nil {
		return stdout, stderr, exitCode, nil
	}

	// Preserve first-attempt diagnostics before retrying.
	firstStdout := stdout
	firstStderr := stderr
	firstExitCode := exitCode
	firstErr := err

	logToolRetry(
		toolName,
		args,
		firstExitCode,
		firstErr,
		firstStdout,
		firstStderr,
	)

	// -------------------------------------------------------------------------
	// Second attempt
	//
	// We deliberately do NOT overwrite the first-attempt information until
	// after it has been logged.
	// -------------------------------------------------------------------------

	secondStdout, secondStderr, secondExitCode, secondErr := executeOnce(
		resolvedTool,
		toolName,
		args,
		timeoutSecs,
	)

	// -------------------------------------------------------------------------
	// Successful retry
	// -------------------------------------------------------------------------

	if secondExitCode == 0 && secondErr == nil {
		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "TOOL_RECOVERED",
			URL:       "",
			RuleType:  fmt.Sprintf("Args: %s", strings.Join(args, " ")),
			Pattern: fmt.Sprintf(
				"Tool: %s FirstExit: %d SecondExit: %d",
				toolName,
				firstExitCode,
				secondExitCode,
			),
			Message: fmt.Sprintf(
				"Tool %s failed first attempt but succeeded on retry. "+
					"First error: %v; First stderr: %s",
				toolName,
				firstErr,
				truncate(firstStderr, 4096),
			),
		})

		return secondStdout, secondStderr, secondExitCode, secondErr
	}

	// -------------------------------------------------------------------------
	// Both attempts failed.
	// -------------------------------------------------------------------------

	finalMessage := fmt.Sprintf(
		"Tool %s failed twice. "+
			"Attempt 1: exit=%d err=%v stderr=%s | "+
			"Attempt 2: exit=%d err=%v stderr=%s",
		toolName,
		firstExitCode,
		firstErr,
		truncate(firstStderr, 4096),
		secondExitCode,
		secondErr,
		truncate(secondStderr, 4096),
	)

	logToolFailure(
		toolName,
		args,
		secondExitCode,
		secondErr,
		secondStderr,
		finalMessage,
	)

	// Return the second attempt because it is the final execution result.
	//
	// The first attempt remains available in the audit log.
	return secondStdout, secondStderr, secondExitCode, secondErr
}

// executeOnce performs exactly one execution of an external tool.
//
// resolvedTool is the path returned by exec.LookPath().
// toolName is retained separately so audit messages contain the friendly
// executable name.
func executeOnce(
	resolvedTool string,
	toolName string,
	args []string,
	timeoutSecs int,
) (stdout string, stderr string, exitCode int, err error) {

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutSecs)*time.Second,
	)
	defer cancel()

	// -------------------------------------------------------------------------
	// Build command
	// -------------------------------------------------------------------------

	cmd := exec.CommandContext(
		ctx,
		resolvedTool,
		args...,
	)

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// -------------------------------------------------------------------------
	// Execute
	// -------------------------------------------------------------------------

	runErr := cmd.Run()

	stdout = outBuf.String()
	stderr = errBuf.String()

	// -------------------------------------------------------------------------
	// Determine exit status.
	//
	// Check the context first so a process killed because of our timeout is
	// explicitly reported as a timeout rather than merely an ExitError.
	// -------------------------------------------------------------------------

	exitCode = 0

	if ctx.Err() == context.DeadlineExceeded {
		exitCode = 124

		err = fmt.Errorf(
			"tool %s timed out after %d seconds",
			toolName,
			timeoutSecs,
		)
	} else if runErr != nil {
		err = runErr

		if exitError, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()

			// Some platforms can return -1 when the process terminates
			// abnormally. Normalize that into a useful non-zero status.
			if exitCode < 0 {
				exitCode = 1
			}
		} else {
			// The executable could be resolved but the process could not
			// otherwise be started.
			exitCode = 1
		}
	}

	// -------------------------------------------------------------------------
	// Audit execution details.
	//
	// Keep stdout + stderr bounded so a noisy tool cannot flood the log.
	// -------------------------------------------------------------------------

	combinedOutput := stdout

	if stderr != "" {
		if combinedOutput != "" {
			combinedOutput += "\n"
		}

		combinedOutput += stderr
	}

	combinedOutput = truncate(combinedOutput, 4096)

	exitStatus := fmt.Sprintf("%d", exitCode)

	if ctx.Err() == context.DeadlineExceeded {
		exitStatus = "TIMEOUT"
	}

	message := fmt.Sprintf(
		"Tool=%s Exit=%s Error=%v Output=%s",
		toolName,
		exitStatus,
		err,
		combinedOutput,
	)

	shared.LogAudit(shared.AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "TOOL_EXECUTION",
		URL:       "",
		RuleType:  fmt.Sprintf("Args: %s", strings.Join(args, " ")),
		Pattern:   fmt.Sprintf("Exit: %s", exitStatus),
		Message:   message,
	})

	return stdout, stderr, exitCode, err
}

// logToolRetry records the complete first-attempt failure before the retry
// happens.
func logToolRetry(
	toolName string,
	args []string,
	exitCode int,
	err error,
	stdout string,
	stderr string,
) {
	shared.LogAudit(shared.AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "TOOL_RETRY",
		URL:       "",
		RuleType:  fmt.Sprintf("Args: %s", strings.Join(args, " ")),
		Pattern:   fmt.Sprintf(
			"Tool: %s Exit: %d",
			toolName,
			exitCode,
		),
		Message: fmt.Sprintf(
			"First attempt failed. Error=%v; stdout=%s; stderr=%s",
			err,
			truncate(stdout, 4096),
			truncate(stderr, 4096),
		),
	})
}

// logToolFailure records the final failure with both attempts represented
// in the message supplied by Execute().
func logToolFailure(
	toolName string,
	args []string,
	exitCode int,
	err error,
	stderr string,
	message string,
) {
	shared.LogAudit(shared.AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "TOOL_FAILURE",
		URL:       "",
		RuleType:  fmt.Sprintf("Args: %s", strings.Join(args, " ")),
		Pattern: fmt.Sprintf(
			"Tool: %s Exit: %d",
			toolName,
			exitCode,
		),
		Message: fmt.Sprintf(
			"%s | FinalError=%v | FinalStderr=%s",
			message,
			err,
			truncate(stderr, 4096),
		),
	})
}

// truncate prevents tool output from making audit records enormous.
func truncate(value string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}

	if len(value) <= maxLen {
		return value
	}

	return value[:maxLen] + "...[truncated]"
}

// getPATH returns the current PATH for diagnostic logging.
func getPATH() string {
	return strings.TrimSpace(
		// os.Getenv is deliberately kept behind this helper so PATH logging
		// remains centralized.
		getEnv("PATH"),
	)
}

// getEnv exists to keep environment access isolated and easy to replace
// during testing.
func getEnv(key string) string {
	// Importing os directly in the main execution path isn't necessary;
	// this helper is the single environment access point.
	return os.Getenv(key)
}

var (
	// osLookupEnv is a variable that can be overridden in tests
	osLookupEnv = os.Getenv
)