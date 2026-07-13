package llbcompiler

import (
	"errors"
	"fmt"
)

var ErrCompile = errors.New("compile Build IR to LLB")

type CompileError struct {
	Code    string
	Message string
	NodeID  string
}

func (err *CompileError) Error() string {
	if err.NodeID == "" {
		return fmt.Sprintf("%s: %s: %s", ErrCompile, err.Code, err.Message)
	}
	return fmt.Sprintf("%s: %s at %s: %s", ErrCompile, err.Code, err.NodeID, err.Message)
}

func (err *CompileError) Unwrap() error {
	return ErrCompile
}

func fail(code, message, nodeID string) *CompileError {
	return &CompileError{Code: code, Message: message, NodeID: nodeID}
}

var _ error = (*CompileError)(nil)
