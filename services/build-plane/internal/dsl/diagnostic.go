package dsl

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

var (
	ErrCompile       = errors.New("compile Lrailfile")
	positionPattern  = regexp.MustCompile(`^(?:.*?):([1-9][0-9]*):([1-9][0-9]*):`)
	identifierFilter = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$|^<toplevel>$`)
)

type Diagnostic struct {
	Severity  string      `json:"severity"`
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	File      string      `json:"file"`
	Line      int         `json:"line"`
	Column    int         `json:"column"`
	Rule      string      `json:"rule"`
	Hint      string      `json:"hint,omitempty"`
	CallStack []CallFrame `json:"call_stack"`
}

type CallFrame struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Function string `json:"function"`
}

type CompileError struct {
	Diagnostic Diagnostic
}

func (err *CompileError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrCompile, err.Diagnostic.Code, err.Diagnostic.Message)
}

func (err *CompileError) Unwrap() error {
	return ErrCompile
}

type ruleError struct {
	code    string
	message string
	rule    string
	hint    string
	pos     syntax.Position
}

func (err *ruleError) Error() string {
	return err.code
}

func failure(code, message, rule, hint, file string, line, column int) *CompileError {
	return &CompileError{Diagnostic: Diagnostic{
		Severity:  "error",
		Code:      code,
		Message:   message,
		File:      safeDiagnosticFile(file),
		Line:      max(line, 1),
		Column:    max(column, 1),
		Rule:      rule,
		Hint:      hint,
		CallStack: []CallFrame{},
	}}
}

func positionedFailure(code, message, rule, hint string, pos syntax.Position) *CompileError {
	return failure(code, message, rule, hint, pos.Filename(), int(pos.Line), int(pos.Col))
}

func builtinFailure(thread *starlark.Thread, code, message, rule, hint string) error {
	position := syntax.Position{}
	for depth := 0; depth < thread.CallStackDepth(); depth++ {
		candidate := thread.CallFrame(depth).Pos
		if candidate.IsValid() && candidate.Filename() != "<builtin>" {
			position = candidate
			break
		}
	}
	return &ruleError{code: code, message: message, rule: rule, hint: hint, pos: position}
}

func compileFailure(err error, fallbackFile string, cancellation *ruleError) *CompileError {
	var existing *CompileError
	if errors.As(err, &existing) {
		return existing
	}
	if cancellation != nil {
		result := positionedFailure(cancellation.code, cancellation.message, cancellation.rule, cancellation.hint, cancellation.pos)
		if evaluation, ok := evalError(err); ok {
			applyEvaluationContext(&result.Diagnostic, evaluation, fallbackFile)
		}
		return result
	}

	var policy *ruleError
	if errors.As(err, &policy) {
		result := positionedFailure(policy.code, policy.message, policy.rule, policy.hint, policy.pos)
		if evaluation, ok := evalError(err); ok {
			applyEvaluationContext(&result.Diagnostic, evaluation, fallbackFile)
		}
		return result
	}

	var syntaxError syntax.Error
	if errors.As(err, &syntaxError) {
		return positionedFailure(
			"dsl.syntax",
			"Starlark source is not valid under the Lrail language profile.",
			"syntax.valid",
			"Correct the syntax at the reported location; host paths and source values are intentionally omitted.",
			syntaxError.Pos,
		)
	}

	result := failure(
		"dsl.evaluation",
		"Starlark evaluation failed under the constrained language profile.",
		"evaluation.valid",
		"Check owned built-in names, named arguments, and value types at the reported call site.",
		fallbackFile,
		1,
		1,
	)
	if evaluation, ok := evalError(err); ok {
		applyEvaluationContext(&result.Diagnostic, evaluation, fallbackFile)
		return result
	}
	if match := positionPattern.FindStringSubmatch(err.Error()); len(match) == 3 {
		result.Diagnostic.Line, _ = strconv.Atoi(match[1])
		result.Diagnostic.Column, _ = strconv.Atoi(match[2])
	}
	return result
}

func evalError(err error) (*starlark.EvalError, bool) {
	var evaluation *starlark.EvalError
	return evaluation, errors.As(err, &evaluation)
}

func applyEvaluationContext(diagnostic *Diagnostic, evaluation *starlark.EvalError, fallbackFile string) {
	frames := make([]CallFrame, 0, len(evaluation.CallStack))
	for _, frame := range evaluation.CallStack {
		file := safeDiagnosticFile(frame.Pos.Filename())
		if file == "Lrailfile.star" && frame.Pos.Filename() != "Lrailfile.star" {
			file = safeDiagnosticFile(fallbackFile)
		}
		function := frame.Name
		if !identifierFilter.MatchString(function) {
			function = "<toplevel>"
		}
		frames = append(frames, CallFrame{
			File:     file,
			Line:     max(int(frame.Pos.Line), 1),
			Column:   max(int(frame.Pos.Col), 1),
			Function: function,
		})
	}
	if len(frames) > 0 {
		top := frames[len(frames)-1]
		if top.File == "<builtin>" && len(frames) > 1 {
			top = frames[len(frames)-2]
		}
		diagnostic.File = top.File
		diagnostic.Line = top.Line
		diagnostic.Column = top.Column
	}
	diagnostic.CallStack = frames
}

func safeDiagnosticFile(value string) string {
	if value == "<builtin>" {
		return value
	}
	if validEntryFilename(value) || validModuleName(value) {
		return value
	}
	return "Lrailfile.star"
}

var _ error = (*CompileError)(nil)
