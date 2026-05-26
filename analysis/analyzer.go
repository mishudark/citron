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
		// Check for shadowing of pure builtins
		switch node := n.(type) {
		case *syntax.AssignStmt:
			syntax.Walk(node.LHS, func(lhsNode syntax.Node) bool {
				if id, ok := lhsNode.(*syntax.Ident); ok {
					if pureBuiltins[id.Name] {
						start, _ := node.Span()
						issues = append(issues, Issue{
							Pos:     start,
							Code:    "SHADOWED_PURE_BUILTIN",
							Message: fmt.Sprintf("cannot shadow pure builtin '%s'", id.Name),
						})
					}
				}
				return true
			})
		case *syntax.DefStmt:
			if pureBuiltins[node.Name.Name] {
				start, _ := node.Span()
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "SHADOWED_PURE_BUILTIN",
					Message: fmt.Sprintf("cannot shadow pure builtin '%s'", node.Name.Name),
				})
			}
		case *syntax.ForStmt:
			syntax.Walk(node.Vars, func(varNode syntax.Node) bool {
				if id, ok := varNode.(*syntax.Ident); ok {
					if pureBuiltins[id.Name] {
						start, _ := node.Span()
						issues = append(issues, Issue{
							Pos:     start,
							Code:    "SHADOWED_PURE_BUILTIN",
							Message: fmt.Sprintf("cannot shadow pure builtin '%s'", id.Name),
						})
					}
				}
				return true
			})
		case *syntax.Comprehension:
			for _, clause := range node.Clauses {
				if forClause, ok := clause.(*syntax.ForClause); ok {
					syntax.Walk(forClause.Vars, func(varNode syntax.Node) bool {
						if id, ok := varNode.(*syntax.Ident); ok {
							if pureBuiltins[id.Name] {
								start, _ := node.Span()
								issues = append(issues, Issue{
									Pos:     start,
									Code:    "SHADOWED_PURE_BUILTIN",
									Message: fmt.Sprintf("cannot shadow pure builtin '%s'", id.Name),
								})
							}
						}
						return true
					})
				}
			}
		case *syntax.LoadStmt:
			for i, to := range node.To {
				name := to.Name
				if name == "" {
					name = node.From[i].Name
				}
				if pureBuiltins[name] {
					start, _ := node.Span()
					issues = append(issues, Issue{
						Pos:     start,
						Code:    "SHADOWED_PURE_BUILTIN",
						Message: fmt.Sprintf("cannot shadow pure builtin '%s' via load", name),
					})
				}
			}
		}

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
