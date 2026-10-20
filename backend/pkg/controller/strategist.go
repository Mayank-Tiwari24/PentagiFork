package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
)

// Strategist uses an LLM to analyze why a subtask failed and produces a
// concrete set of SubtaskOperations (add / modify / remove / reorder) that the
// task controller can apply to recover the flow.
type Strategist struct {
	provider provider.Provider
}

// NewStrategist creates a Strategist backed by the given LLM provider. If
// provider is nil the strategist falls back to a deterministic recovery
// heuristic (modify the failed task with a richer description).
func NewStrategist(p provider.Provider) *Strategist {
	return &Strategist{provider: p}
}

// recoveryPrompt builds the prompt sent to the LLM when analyzing a failure.
func recoveryPrompt(failedTask tools.SubtaskInfo, errorLog string, flowState *FlowContext) string {
	var sb strings.Builder
	sb.WriteString("You are an autonomous penetration-testing strategist.\n\n")
	sb.WriteString("A subtask has failed. Analyze the error and the current flow state, ")
	sb.WriteString("then return a JSON array of recovery operations.\n\n")

	sb.WriteString("## Failed Subtask\n")
	sb.WriteString(fmt.Sprintf("- Title: %s\n", failedTask.Title))
	sb.WriteString(fmt.Sprintf("- Description: %s\n", failedTask.Description))

	sb.WriteString("\n## Error Log\n```\n")
	// Truncate very long error logs to stay within token budget.
	const maxErrLen = 4096
	if len(errorLog) > maxErrLen {
		sb.WriteString(errorLog[:maxErrLen])
		sb.WriteString("\n...[truncated]")
	} else {
		sb.WriteString(errorLog)
	}
	sb.WriteString("\n```\n")

	sb.WriteString("\n## Flow Context\n")
	sb.WriteString(fmt.Sprintf("- Flow ID: %d\n", flowState.FlowID))

	sb.WriteString("\n## Response Format\n")
	sb.WriteString("Return ONLY a JSON array of operations. Each operation is an object with:\n")
	sb.WriteString(`- "op": one of "add", "modify", "remove", "reorder"` + "\n")
	sb.WriteString(`- "id": (required for modify/remove/reorder) integer ID of the subtask` + "\n")
	sb.WriteString(`- "title": (required for add/modify) new title` + "\n")
	sb.WriteString(`- "description": (required for add/modify) new description` + "\n")
	sb.WriteString("\nExample:\n")
	sb.WriteString("```json\n")
	sb.WriteString(`[{"op":"modify","id":5,"title":"Retry: port scan with adjusted timing","description":"The previous nmap scan timed out. Retry with -T3 timing template and smaller port range."}]`)
	sb.WriteString("\n```\n")

	return sb.String()
}

// AnalyzeFailureAndReplan analyzes a failed task using the flow context and returns a set of subtask operations to recover.
func (s *Strategist) AnalyzeFailureAndReplan(ctx context.Context, failedTaskID int64, failedTask tools.SubtaskInfo, errorLog string, flowState *FlowContext) ([]tools.SubtaskOperation, error) {
	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"failed_task_id": failedTaskID,
		"failed_title":   failedTask.Title,
	})
	logger.Info("Strategist analyzing task failure")

	// Fallback: if no LLM provider is available, use a deterministic recovery.
	if s.provider == nil {
		logger.Warn("no LLM provider configured for strategist, using deterministic fallback")
		return s.deterministicFallback(failedTaskID, failedTask, errorLog), nil
	}

	prompt := recoveryPrompt(failedTask, errorLog, flowState)

	response, err := s.provider.Call(ctx, pconfig.OptionsTypeSimple, prompt)
	if err != nil {
		logger.WithError(err).Warn("LLM call failed for strategist, using deterministic fallback")
		return s.deterministicFallback(failedTaskID, failedTask, errorLog), nil
	}

	ops, err := parseRecoveryOps(response, failedTaskID)
	if err != nil {
		logger.WithError(err).Warn("failed to parse LLM recovery response, using deterministic fallback")
		return s.deterministicFallback(failedTaskID, failedTask, errorLog), nil
	}

	if len(ops) == 0 {
		logger.Warn("LLM returned empty recovery ops, using deterministic fallback")
		return s.deterministicFallback(failedTaskID, failedTask, errorLog), nil
	}

	logger.WithField("ops_count", len(ops)).Info("Strategist produced recovery operations via LLM")
	return ops, nil
}

// deterministicFallback produces a simple modify operation when the LLM is
// unavailable or returns unparseable output.
func (s *Strategist) deterministicFallback(failedTaskID int64, failedTask tools.SubtaskInfo, errorLog string) []tools.SubtaskOperation {
	// Truncate error log for the description to keep it reasonable.
	const maxDescErr = 2048
	truncatedErr := errorLog
	if len(truncatedErr) > maxDescErr {
		truncatedErr = truncatedErr[:maxDescErr] + "...[truncated]"
	}

	return []tools.SubtaskOperation{
		{
			Op:          tools.SubtaskOpModify,
			ID:          &failedTaskID,
			Title:       fmt.Sprintf("RECOVER: %s", failedTask.Title),
			Description: fmt.Sprintf("Previous attempt failed with error: %s. Re-evaluate and try an alternative approach.", truncatedErr),
		},
	}
}

// parseRecoveryOps extracts the JSON operation array from the LLM response.
// It tolerates markdown code fences around the JSON.
func parseRecoveryOps(response string, failedTaskID int64) ([]tools.SubtaskOperation, error) {
	// Strip markdown code fences if present.
	cleaned := strings.TrimSpace(response)
	if idx := strings.Index(cleaned, "```json"); idx != -1 {
		cleaned = cleaned[idx+len("```json"):]
	} else if idx := strings.Index(cleaned, "```"); idx != -1 {
		cleaned = cleaned[idx+len("```"):]
	}
	if idx := strings.LastIndex(cleaned, "```"); idx != -1 {
		cleaned = cleaned[:idx]
	}
	cleaned = strings.TrimSpace(cleaned)

	// Find the JSON array boundaries.
	start := strings.Index(cleaned, "[")
	end := strings.LastIndex(cleaned, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found in response")
	}
	cleaned = cleaned[start : end+1]

	var rawOps []struct {
		Op          string  `json:"op"`
		ID          *int64  `json:"id"`
		Title       string  `json:"title"`
		Description string  `json:"description"`
	}

	if err := json.Unmarshal([]byte(cleaned), &rawOps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal recovery ops: %w", err)
	}

	ops := make([]tools.SubtaskOperation, 0, len(rawOps))
	for _, raw := range rawOps {
		op := tools.SubtaskOperation{
			Op:          tools.SubtaskOperationType(raw.Op),
			Title:       raw.Title,
			Description: raw.Description,
		}
		// For modify/remove/reorder, ensure there's always an ID.
		if raw.ID != nil {
			op.ID = raw.ID
		} else if raw.Op == string(tools.SubtaskOpModify) || raw.Op == string(tools.SubtaskOpRemove) || raw.Op == string(tools.SubtaskOpReorder) {
			op.ID = &failedTaskID
		}
		ops = append(ops, op)
	}

	return ops, nil
}
