package tools

import "errors"

// ErrToolCrash is a sentinel error indicating that a tool or its runtime environment
// has crashed (e.g. sandbox container stopped/dead, segmentation fault, OOM killed,
// or critical runtime failure).
// When ErrToolCrash is encountered, the execution pipeline immediately halts
// and transitions the flow to the Waiting state (pausing execution for human inspection)
// instead of burning tokens on argument-correction or blind retries.
var ErrToolCrash = errors.New("tool execution crashed")

// toolCrashError marks err so errors.Is(err, ErrToolCrash) reports true,
// preserving the underlying error message.
type toolCrashError struct{ error }

func (e toolCrashError) Is(target error) bool { return target == ErrToolCrash }
func (e toolCrashError) Unwrap() error        { return e.error }

// ToolCrash wraps an error as an ErrToolCrash.
func ToolCrash(err error) error {
	if err == nil {
		return ErrToolCrash
	}
	return toolCrashError{err}
}
