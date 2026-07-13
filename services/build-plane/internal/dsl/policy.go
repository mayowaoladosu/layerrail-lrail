package dsl

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"go.starlark.net/syntax"
)

var fileOptions = &syntax.FileOptions{
	TopLevelControl: true,
}

var allocationBuiltins = []string{
	"bytes",
	"dict",
	"dir",
	"enumerate",
	"getattr",
	"hasattr",
	"list",
	"print",
	"range",
	"repr",
	"reversed",
	"set",
	"sorted",
	"str",
	"tuple",
	"zip",
}

func validateSourceBytes(filename string, source []byte, limits Limits) *CompileError {
	if len(source) == 0 {
		return failure(
			"dsl.source_empty",
			"Starlark source must not be empty.",
			"source.nonempty",
			"Provide a bounded UTF-8 Lrailfile or module.",
			filename,
			1,
			1,
		)
	}
	if len(source) > limits.MaxSourceBytes {
		return failure(
			"dsl.source_size",
			"Starlark source exceeds the configured aggregate byte limit.",
			"limits.source_bytes",
			fmt.Sprintf("Keep the entry file and loaded modules within %d bytes.", limits.MaxSourceBytes),
			filename,
			1,
			1,
		)
	}
	if !utf8.Valid(source) || strings.IndexByte(string(source), 0) >= 0 {
		return failure(
			"dsl.source_encoding",
			"Starlark source must be valid UTF-8 without NUL bytes.",
			"source.utf8",
			"Encode source as UTF-8 and remove binary content.",
			filename,
			1,
			1,
		)
	}
	return nil
}

func validateSyntaxPolicy(file *syntax.File, limits Limits, priorNodes int) (int, *CompileError) {
	count := priorNodes
	var policyFailure *CompileError
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil || policyFailure != nil {
			return false
		}
		count++
		if count > limits.MaxASTNodes {
			policyFailure = positionedFailure(
				"dsl.ast_limit",
				"Starlark syntax exceeds the aggregate AST node limit.",
				"limits.ast_nodes",
				fmt.Sprintf("Reduce the entry file and loaded modules to at most %d syntax nodes.", limits.MaxASTNodes),
				syntax.Start(node),
			)
			return false
		}

		switch typed := node.(type) {
		case *syntax.ForStmt, *syntax.WhileStmt, *syntax.Comprehension:
			policyFailure = unsupportedSyntax(
				syntax.Start(node),
				"Unbounded iteration is not available in the Lrail v1 language profile.",
				"Use bounded literals and explicit owned built-in calls.",
			)
		case *syntax.LambdaExpr:
			policyFailure = unsupportedSyntax(
				typed.Lambda,
				"Lambda expressions are not available in the Lrail v1 language profile.",
				"Declare a named helper function with a bounded call graph.",
			)
		case *syntax.DotExpr:
			policyFailure = unsupportedSyntax(
				typed.Dot,
				"Method and attribute access are not available in the Lrail v1 language profile.",
				"Use immutable values and owned built-ins instead of mutable methods or host-like objects.",
			)
		case *syntax.SliceExpr:
			policyFailure = unsupportedSyntax(
				typed.Lbrack,
				"Slicing is not available in the Lrail v1 language profile.",
				"Pass bounded complete values to owned built-ins.",
			)
		case *syntax.BranchStmt:
			policyFailure = unsupportedSyntax(
				typed.TokenPos,
				"Loop branch statements are not available in the Lrail v1 language profile.",
				"Remove loop control from the build definition.",
			)
		case *syntax.AssignStmt:
			if typed.Op != syntax.EQ || !safeAssignmentTarget(typed.LHS) {
				policyFailure = unsupportedSyntax(
					typed.OpPos,
					"Mutation and augmented assignment are not available in the Lrail v1 language profile.",
					"Bind a new local identifier with a plain assignment.",
				)
			}
		case *syntax.BinaryExpr:
			if !slices.Contains([]syntax.Token{syntax.AND, syntax.OR, syntax.EQL, syntax.NEQ, syntax.LT, syntax.LE, syntax.GT, syntax.GE, syntax.IN, syntax.NOT_IN, syntax.EQ}, typed.Op) {
				policyFailure = unsupportedSyntax(
					typed.OpPos,
					"Potentially amplifying arithmetic and collection operators are not available in the Lrail v1 language profile.",
					"Use comparisons, boolean logic, and bounded owned built-ins.",
				)
			}
		case *syntax.UnaryExpr:
			if !slices.Contains([]syntax.Token{syntax.NOT, syntax.MINUS, syntax.PLUS, syntax.TILDE}, typed.Op) {
				policyFailure = unsupportedSyntax(
					typed.OpPos,
					"Variadic expansion is not available in the Lrail v1 language profile.",
					"Pass explicit bounded arguments.",
				)
			}
		case *syntax.Literal:
			if typed.Token == syntax.BYTES {
				policyFailure = unsupportedSyntax(
					typed.TokenPos,
					"Byte literals are not available in the Lrail v1 language profile.",
					"Use bounded UTF-8 strings.",
				)
				break
			}
			if text, ok := typed.Value.(string); ok && len(text) > limits.MaxStringBytes {
				policyFailure = positionedFailure(
					"dsl.string_limit",
					"A Starlark string literal exceeds the configured byte limit.",
					"limits.string_bytes",
					fmt.Sprintf("Keep each string within %d UTF-8 bytes.", limits.MaxStringBytes),
					typed.TokenPos,
				)
			}
		case *syntax.ListExpr:
			policyFailure = collectionLimitFailure(len(typed.List), limits, typed.Lbrack)
		case *syntax.TupleExpr:
			policyFailure = collectionLimitFailure(len(typed.List), limits, syntax.Start(typed))
		case *syntax.DictExpr:
			policyFailure = collectionLimitFailure(len(typed.List), limits, typed.Lbrace)
		case *syntax.CallExpr:
			if len(typed.Args) > limits.MaxCollectionItems {
				policyFailure = collectionLimitFailure(len(typed.Args), limits, typed.Lparen)
				break
			}
			identifier, ok := typed.Fn.(*syntax.Ident)
			if !ok {
				policyFailure = unsupportedSyntax(
					syntax.Start(typed.Fn),
					"Dynamic callable expressions are not available in the Lrail v1 language profile.",
					"Call a statically named helper or owned Lrail built-in.",
				)
				break
			}
			if slices.Contains(allocationBuiltins, identifier.Name) {
				policyFailure = unsupportedSyntax(
					identifier.NamePos,
					"The requested universal built-in is not available in the Lrail v1 language profile.",
					"Use bounded literals and the owned Lrail built-ins.",
				)
			}
		case *syntax.Ident:
			if slices.Contains(allocationBuiltins, typed.Name) {
				policyFailure = unsupportedSyntax(
					typed.NamePos,
					"The requested universal built-in cannot be referenced in the Lrail v1 language profile.",
					"Use bounded literals and immutable owned Lrail built-ins.",
				)
			}
		case *syntax.DefStmt:
			if len(typed.Params) > limits.MaxCollectionItems {
				policyFailure = collectionLimitFailure(len(typed.Params), limits, typed.Lparen)
			}
		case *syntax.LoadStmt:
			if len(typed.From) > limits.MaxCollectionItems {
				policyFailure = collectionLimitFailure(len(typed.From), limits, typed.Load)
			}
		}
		return policyFailure == nil
	})
	return count, policyFailure
}

func unsupportedSyntax(position syntax.Position, message, hint string) *CompileError {
	return positionedFailure(
		"dsl.unsupported_syntax",
		message,
		"syntax.bounded_profile",
		hint,
		position,
	)
}

func collectionLimitFailure(count int, limits Limits, position syntax.Position) *CompileError {
	if count <= limits.MaxCollectionItems {
		return nil
	}
	return positionedFailure(
		"dsl.collection_limit",
		"A Starlark collection exceeds the configured item limit.",
		"limits.collection_items",
		fmt.Sprintf("Keep each collection within %d items.", limits.MaxCollectionItems),
		position,
	)
}

func safeAssignmentTarget(expression syntax.Expr) bool {
	switch typed := expression.(type) {
	case *syntax.Ident:
		return true
	case *syntax.TupleExpr:
		for _, item := range typed.List {
			if !safeAssignmentTarget(item) {
				return false
			}
		}
		return true
	case *syntax.ParenExpr:
		return safeAssignmentTarget(typed.X)
	default:
		return false
	}
}
