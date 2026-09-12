package cli

import "errors"

// ExitError carries the process status required by a command while keeping
// Cobra's normal error propagation and testability.
type ExitError struct {
	Status int
	Err    error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ExitError) ExitCode() int {
	if e == nil {
		return 1
	}
	return e.Status
}

// ExitCode maps a command error to the process exit status in the product
// contract. Ordinary command failures retain the existing status 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		code := coded.ExitCode()
		if code > 0 {
			return code
		}
	}
	return 1
}
