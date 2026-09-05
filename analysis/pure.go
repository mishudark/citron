package analysis

import (
	"fmt"

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

// capabilityNames are the global capability objects injected by the citron
// harness. They must never be referenced inside map/flat_map callbacks:
// the callback receives the unwrapped classified value, so a capability
// reference (even aliased) is an exfiltration channel.
var capabilityNames = map[string]bool{
	"fs": true, "io": true, "net": true, "proc": true,
}

// IsPureBuiltin reports whether name is a Starlark builtin the analyzer
// treats as pure and therefore permits inside map/flat_map callbacks.
// Callers that inject additional globals (e.g. remote MCP tool bindings)
// must reject names in this set: such a global would shadow the builtin and
// defeat callback purity verification.
func IsPureBuiltin(name string) bool {
	return pureBuiltins[name]
}

func checkCallbackPurity(cb syntax.Expr, defs map[string]*syntax.DefStmt, ambiguous map[string]bool, capAliases map[string]bool) []Issue {
	var body syntax.Node

	switch v := cb.(type) {
	case *syntax.LambdaExpr:
		body = v.Body
	case *syntax.Ident:
		if ambiguous[v.Name] {
			start, _ := v.Span()
			return []Issue{{
				Pos:  start,
				Code: "AMBIGUOUS_CALLBACK_DEF",
				Message: fmt.Sprintf("function '%s' is defined or bound more than once; "+
					"Starlark resolves to the last binding, so callback purity cannot be verified", v.Name),
			}}
		}
		def, ok := defs[v.Name]
		if !ok {
			// Pure builtins like str/int/len are valid map callbacks.
			if pureBuiltins[v.Name] {
				return nil
			}
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

	return checkBodyPurity(body, capAliases)
}

func checkBodyPurity(body syntax.Node, capAliases map[string]bool) []Issue {
	var issues []Issue

	// Names bound anywhere inside the callback (parameters, loop variables,
	// plain assignments) are locals in Starlark: a local that shadows a
	// capability or alias name is harmless data, not a capability reference.
	bound := make(map[string]bool)
	collectLocalBindings(body, bound)

	syntax.Walk(body, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.Ident:
			if (capabilityNames[node.Name] || capAliases[node.Name]) && !bound[node.Name] {
				start, _ := node.Span()
				issues = append(issues, Issue{
					Pos:  start,
					Code: "IMPURE_CAPABILITY_REF",
					Message: fmt.Sprintf("reference to '%s' inside pure callback is forbidden: "+
						"capabilities (or values holding them) cannot be captured or used here", node.Name),
				})
			}
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

// collectLocalBindings records every name bound within a callback body:
// function parameters (including nested defs and lambdas), for-loop and
// comprehension variables, and assignment targets. In Starlark any name
// assigned in a function is local for the whole function scope.
func collectLocalBindings(body syntax.Node, bound map[string]bool) {
	syntax.Walk(body, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.DefStmt:
			for _, p := range node.Params {
				bindParam(p, bound)
			}
		case *syntax.LambdaExpr:
			for _, p := range node.Params {
				bindParam(p, bound)
			}
		case *syntax.ForStmt:
			bindIdentExpr(node.Vars, bound)
		case *syntax.Comprehension:
			for _, clause := range node.Clauses {
				if forClause, ok := clause.(*syntax.ForClause); ok {
					bindIdentExpr(forClause.Vars, bound)
				}
			}
		case *syntax.AssignStmt:
			bindIdentExpr(node.LHS, bound)
		}
		return true
	})
}

// bindParam records a function parameter name, covering the
// `name`, `name=default`, `*args`, and `**kwargs` forms without treating
// default expressions as bindings.
func bindParam(p syntax.Expr, bound map[string]bool) {
	switch v := p.(type) {
	case *syntax.Ident:
		bound[v.Name] = true
	case *syntax.BinaryExpr:
		if id, ok := v.X.(*syntax.Ident); ok {
			bound[id.Name] = true
		}
	case *syntax.UnaryExpr:
		if v.X != nil {
			bindParam(v.X, bound)
		}
	}
}

// bindIdentExpr records every identifier in an assignment target or loop
// variable expression.
func bindIdentExpr(e syntax.Expr, bound map[string]bool) {
	syntax.Walk(e, func(n syntax.Node) bool {
		if id, ok := n.(*syntax.Ident); ok {
			bound[id.Name] = true
		}
		return true
	})
}
