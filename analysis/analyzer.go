package analysis

import (
	"fmt"
	"go.starlark.net/syntax"
)

type Issue struct {
	Pos     syntax.Position
	Code    string
	Message string
}

func (i Issue) Error() string {
	return fmt.Sprintf("%s: %s (%s)", i.Pos, i.Message, i.Code)
}

// Analyze checks a Starlark script for capability-safety violations.
func Analyze(filename string, code []byte) ([]Issue, error) {
	f, err := new(syntax.FileOptions).Parse(filename, code, 0)
	if err != nil {
		return nil, fmt.Errorf("syntax error: %w", err)
	}

	var issues []Issue

	// Build a map of ALL function definitions (including nested) for reference resolution.
	defs := make(map[string]*syntax.DefStmt)
	syntax.Walk(f, func(n syntax.Node) bool {
		if def, ok := n.(*syntax.DefStmt); ok {
			if _, exists := defs[def.Name.Name]; !exists {
				defs[def.Name.Name] = def
			}
		}
		return true
	})

	// First pass: build set of variables that hold Classified values.
	classifiedVars := buildClassifiedVarSet(f.Stmts)

	syntax.Walk(f, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		dot, ok := call.Fn.(*syntax.DotExpr)
		if !ok {
			return true
		}
		if dot.Name.Name == "map" || dot.Name.Name == "flat_map" {
			start, _ := call.Span()
			if len(call.Args) != 1 {
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "INVALID_MAP_ARGS",
					Message: "map/flat_map requires exactly one argument",
				})
				return true
			}

			cb := call.Args[0]
			iss := checkCallbackPurity(cb, defs)
			issues = append(issues, iss...)
		}
		if dot.Name.Name == "write" && len(call.Args) > 0 {
			// Check if the content argument is a Classified value.
			arg := call.Args[0]
			if exprProducesClassified(arg, classifiedVars) {
				start, _ := call.Span()
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "CLASSIFIED_WRITE_MISMATCH",
					Message: "write expects a string, but the content argument is Classified data; use write_classified or unwrap via map first",
				})
			}
		}
		return true
	})

	return issues, nil
}

// buildClassifiedVarSet walks top-level statements in order and tracks
// which variable names hold Classified values.
func buildClassifiedVarSet(stmts []syntax.Stmt) map[string]bool {
	classified := make(map[string]bool)

	for _, stmt := range stmts {
		assign, ok := stmt.(*syntax.AssignStmt)
		if !ok || assign.Op != syntax.EQ {
			continue
		}
		lhs, ok := assign.LHS.(*syntax.Ident)
		if !ok {
			continue
		}
		if exprProducesClassified(assign.RHS, classified) {
			classified[lhs.Name] = true
		}
	}

	return classified
}

// exprProducesClassified checks whether an expression produces a Classified value.
func exprProducesClassified(expr syntax.Expr, classifiedVars map[string]bool) bool {
	switch e := expr.(type) {
	case *syntax.CallExpr:
		if dot, ok := e.Fn.(*syntax.DotExpr); ok {
			// .read_classified(), .map(), .flat_map() all return Classified.
			if dot.Name.Name == "read_classified" || dot.Name.Name == "map" || dot.Name.Name == "flat_map" {
				return true
			}
		}
	case *syntax.Ident:
		return classifiedVars[e.Name]
	}
	return false
}
