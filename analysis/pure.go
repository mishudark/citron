package analysis

import (
	"go.starlark.net/syntax"
)

var pureMethods = map[string]bool{
	"upper": true, "lower": true, "title": true, "capitalize": true,
	"format": true, "strip": true, "lstrip": true, "rstrip": true,
	"replace": true, "split": true, "rsplit": true, "splitlines": true,
	"join": true, "count": true, "find": true, "rfind": true,
	"index": true, "rindex": true, "startswith": true, "endswith": true,
	"isalnum": true, "isalpha": true, "isdigit": true, "islower": true,
	"isspace": true, "istitle": true, "isupper": true,
	"keys": true, "values": true, "items": true, "get": true, "copy": true,
	"map": true, "flat_map": true,
}

var pureBuiltins = map[string]bool{
	"abs": true, "any": true, "all": true, "bool": true,
	"dict": true, "dir": true, "enumerate": true, "float": true,
	"getattr": true, "hasattr": true, "hash": true, "int": true,
	"len": true, "list": true, "max": true, "min": true,
	"range": true, "repr": true, "reversed": true, "set": true,
	"sorted": true, "str": true, "tuple": true, "type": true,
	"zip": true,
}

func checkCallbackPurity(cb syntax.Expr, defs map[string]*syntax.DefStmt) []Issue {
	var body syntax.Node

	switch v := cb.(type) {
	case *syntax.LambdaExpr:
		body = v.Body
	case *syntax.Ident:
		def, ok := defs[v.Name]
		if !ok {
			start, _ := v.Span()
			return []Issue{{
				Pos:     start,
				Code:    "IMPURE_MAP_CALLBACK",
				Message: "map callback must be a lambda or a locally defined function",
			}}
		}
		body = def
	default:
		start, _ := cb.Span()
		return []Issue{{
			Pos:     start,
			Code:    "IMPURE_MAP_CALLBACK",
			Message: "map callback must be a lambda or a locally defined function reference",
		}}
	}

	return checkBodyPurity(body)
}

func checkBodyPurity(body syntax.Node) []Issue {
	var issues []Issue

	syntax.Walk(body, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.AssignStmt:
			if _, ok := node.LHS.(*syntax.IndexExpr); ok {
				start, _ := node.Span()
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "IMPURE_MUTATION",
					Message: "index assignment inside pure callback is forbidden",
				})
			}
			if _, ok := node.LHS.(*syntax.DotExpr); ok {
				start, _ := node.Span()
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "IMPURE_MUTATION",
					Message: "attribute assignment inside pure callback is forbidden",
				})
			}
		case *syntax.CallExpr:
			if dot, ok := node.Fn.(*syntax.DotExpr); ok {
				if !pureMethods[dot.Name.Name] {
					start, _ := node.Span()
					issues = append(issues, Issue{
						Pos:     start,
						Code:    "IMPURE_METHOD_CALL",
						Message: "call to potentially impure method '" + dot.Name.Name + "' inside pure callback is forbidden",
					})
				}
			} else if id, ok := node.Fn.(*syntax.Ident); ok {
				if !pureBuiltins[id.Name] {
					start, _ := node.Span()
					issues = append(issues, Issue{
						Pos:     start,
						Code:    "IMPURE_FUNC_CALL",
						Message: "call to potentially impure function '" + id.Name + "' inside pure callback is forbidden",
					})
				}
			} else {
				start, _ := node.Span()
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "IMPURE_DYNAMIC_CALL",
					Message: "call with dynamic function expression inside pure callback is forbidden",
				})
			}
		}
		return true
	})

	return issues
}
