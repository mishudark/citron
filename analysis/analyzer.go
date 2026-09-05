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
	// Names defined or re-bound more than once are recorded as ambiguous: Starlark
	// resolves calls to the last binding, so a callback referring to such a name
	// cannot be statically verified (the first def might be checked while an
	// impure later def actually runs).
	defs := make(map[string]*syntax.DefStmt)
	ambiguous := make(map[string]bool)
	syntax.Walk(f, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.DefStmt:
			name := node.Name.Name
			if _, exists := defs[name]; exists {
				ambiguous[name] = true
			} else {
				defs[name] = node
			}
		case *syntax.AssignStmt:
			if node.Op != syntax.EQ {
				return true
			}
			syntax.Walk(node.LHS, func(lhs syntax.Node) bool {
				if id, ok := lhs.(*syntax.Ident); ok {
					if _, isDef := defs[id.Name]; isDef {
						ambiguous[id.Name] = true
					}
				}
				return true
			})
		}
		return true
	})

	// First pass: build set of variables that hold Classified values.
	classifiedVars := buildClassifiedVarSet(f)

	// Track global names that may hold capabilities or values derived from
	// them (e.g. `n = net`, `d = {"n": net}`). Referencing such a name inside
	// a map/flat_map callback is an exfiltration channel because the callback
	// receives the unwrapped classified value at runtime.
	capAliases := buildCapabilityAliasSet(f)

	// called records callee expressions that appear in direct call position,
	// so map/flat_map method values used any other way can be flagged.
	called := make(map[syntax.Node]bool)

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
		case *syntax.DotExpr:
			// A map/flat_map method value outside a direct call position
			// (e.g. `m = secret.map`) can be invoked later, bypassing the
			// callback purity check that only inspects direct calls.
			if (node.Name.Name == "map" || node.Name.Name == "flat_map") && !called[node] {
				start, _ := node.Span()
				issues = append(issues, Issue{
					Pos:  start,
					Code: "MAP_METHOD_ALIAS",
					Message: fmt.Sprintf("'%s' method value used outside a direct call; invoke %s(callback) directly so the callback can be verified",
						node.Name.Name, node.Name.Name),
				})
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
		// Mark the callee as used in direct call position so the DotExpr
		// case above can detect smuggled map/flat_map method values.
		called[call.Fn] = true

		// Indirect map/flat_map invocation: getattr(x, "map")(callback).
		// The callback must be verified exactly like a direct call.
		if inner, ok := call.Fn.(*syntax.CallExpr); ok {
			if name, ok := getattrStringArg(inner); ok && (name == "map" || name == "flat_map") {
				start, _ := call.Span()
				if len(call.Args) != 1 {
					issues = append(issues, Issue{
						Pos:     start,
						Code:    "INVALID_MAP_ARGS",
						Message: "map/flat_map requires exactly one argument",
					})
					return true
				}
				iss := checkCallbackPurity(call.Args[0], defs, ambiguous, capAliases)
				issues = append(issues, iss...)
				return true
			}
		}

		if isGetattrCall(call) && len(call.Args) >= 2 {
			if name, ok := getattrStringArg(call); ok {
				// A literal map/flat_map getattr outside call position is a
				// smuggled method value, same as `m = secret.map`.
				if (name == "map" || name == "flat_map") && !called[call] {
					start, _ := call.Span()
					issues = append(issues, Issue{
						Pos:  start,
						Code: "MAP_METHOD_ALIAS",
						Message: fmt.Sprintf("'%s' method value used outside a direct call; invoke %s(callback) directly so the callback can be verified",
							name, name),
					})
				}
			} else if exprProducesClassified(call.Args[0], classifiedVars) {
				// getattr with a dynamic attribute name on classified data can
				// fetch the map/flat_map method, defeating verification.
				start, _ := call.Span()
				issues = append(issues, Issue{
					Pos:     start,
					Code:    "DYNAMIC_GETATTR",
					Message: "getattr with a non-literal attribute name on classified data is forbidden",
				})
			}
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
			iss := checkCallbackPurity(cb, defs, ambiguous, capAliases)
			issues = append(issues, iss...)
		}
		if dot.Name.Name == "write" {
			flagged := false
			checkArg := func(arg syntax.Expr) {
				if exprProducesClassified(arg, classifiedVars) {
					flagged = true
				}
			}
			for _, arg := range call.Args {
				if kw, ok := arg.(*syntax.BinaryExpr); ok && kw.Op == syntax.EQ {
					checkArg(kw.Y)
				} else {
					checkArg(arg)
				}
			}
			if flagged {
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

// buildClassifiedVarSet walks the full AST in source order and tracks which
// variable names hold Classified values, including bindings inside function
// bodies, if/for blocks, and comprehensions. Taint is sticky: reassignment to
// a non-Classified value does not clear the taint, because a conditional
// reassignment must not weaken the guarantee.
func buildClassifiedVarSet(node syntax.Node) map[string]bool {
	classified := make(map[string]bool)
	trackClassified(node, classified)
	return classified
}

func trackClassified(n syntax.Node, classified map[string]bool) {
	if n == nil {
		return
	}
	switch node := n.(type) {
	case *syntax.AssignStmt:
		trackClassified(node.RHS, classified)
		if exprProducesClassified(node.RHS, classified) {
			bindClassified(node.LHS, classified)
		}
		return
	case *syntax.ForStmt:
		trackClassified(node.X, classified)
		if exprProducesClassified(node.X, classified) {
			bindClassified(node.Vars, classified)
		}
		for _, stmt := range node.Body {
			trackClassified(stmt, classified)
		}
		return
	case *syntax.Comprehension:
		for _, clause := range node.Clauses {
			switch cl := clause.(type) {
			case *syntax.ForClause:
				trackClassified(cl.X, classified)
				if exprProducesClassified(cl.X, classified) {
					bindClassified(cl.Vars, classified)
				}
			case *syntax.IfClause:
				trackClassified(cl.Cond, classified)
			}
		}
		trackClassified(node.Body, classified)
		return
	}
	syntax.Walk(n, func(child syntax.Node) bool {
		if child == n {
			return true
		}
		trackClassified(child, classified)
		return false
	})
}

func bindClassified(lhs syntax.Expr, classified map[string]bool) {
	syntax.Walk(lhs, func(n syntax.Node) bool {
		if id, ok := n.(*syntax.Ident); ok {
			classified[id.Name] = true
		}
		return true
	})
}

// exprProducesClassified checks whether an expression produces (or contains)
// a Classified value. Taint propagates through composite expressions:
// concatenation (`"x" + secret`), containers, conditionals, comprehensions,
// and indexing all carry classified taint to the result.
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
	case *syntax.DotExpr:
		return exprProducesClassified(e.X, classifiedVars)
	case *syntax.ParenExpr:
		return exprProducesClassified(e.X, classifiedVars)
	case *syntax.UnaryExpr:
		return e.X != nil && exprProducesClassified(e.X, classifiedVars)
	case *syntax.BinaryExpr:
		return exprProducesClassified(e.X, classifiedVars) || exprProducesClassified(e.Y, classifiedVars)
	case *syntax.IndexExpr:
		return exprProducesClassified(e.X, classifiedVars) || exprProducesClassified(e.Y, classifiedVars)
	case *syntax.SliceExpr:
		return exprProducesClassified(e.X, classifiedVars) ||
			(e.Lo != nil && exprProducesClassified(e.Lo, classifiedVars)) ||
			(e.Hi != nil && exprProducesClassified(e.Hi, classifiedVars)) ||
			(e.Step != nil && exprProducesClassified(e.Step, classifiedVars))
	case *syntax.ListExpr:
		for _, el := range e.List {
			if exprProducesClassified(el, classifiedVars) {
				return true
			}
		}
	case *syntax.TupleExpr:
		for _, el := range e.List {
			if exprProducesClassified(el, classifiedVars) {
				return true
			}
		}
	case *syntax.DictExpr:
		for _, el := range e.List {
			if entry, ok := el.(*syntax.DictEntry); ok {
				if exprProducesClassified(entry.Key, classifiedVars) || exprProducesClassified(entry.Value, classifiedVars) {
					return true
				}
			}
		}
	case *syntax.CondExpr:
		return exprProducesClassified(e.True, classifiedVars) || exprProducesClassified(e.False, classifiedVars)
	case *syntax.Comprehension:
		return exprProducesClassified(e.Body, classifiedVars)
	}
	return false
}

// buildCapabilityAliasSet computes the set of global names that may hold
// capability objects or values derived from them. Direct aliases (`n = net`)
// and container smuggling (`d = {"n": net}`) are covered; the set is
// computed to a fixpoint so chains like `n = net; m = n` are also caught.
// Results of classified operations (read_classified/map/flat_map) are pure
// data and do not propagate the taint, keeping chained classified maps
// inside callbacks working. Assignments inside def bodies are locals and
// are ignored.
func buildCapabilityAliasSet(f *syntax.File) map[string]bool {
	aliases := make(map[string]bool)
	for {
		before := len(aliases)
		syntax.Walk(f, func(n syntax.Node) bool {
			switch node := n.(type) {
			case *syntax.DefStmt:
				return false // assignments inside defs are locals
			case *syntax.AssignStmt:
				if exprHoldsCapability(node.RHS, aliases) {
					bindIdentExpr(node.LHS, aliases)
				}
			case *syntax.ForStmt:
				if exprHoldsCapability(node.X, aliases) {
					bindIdentExpr(node.Vars, aliases)
				}
			}
			return true
		})
		if len(aliases) == before {
			break
		}
	}
	return aliases
}

// exprHoldsCapability reports whether evaluating expr may yield or capture a
// capability object (fs/io/net/proc or an alias). FileEntry handles obtained
// via fs.access are capability handles too. Results of classified
// operations are treated as pure data.
func exprHoldsCapability(expr syntax.Expr, aliases map[string]bool) bool {
	switch e := expr.(type) {
	case *syntax.Ident:
		return capabilityNames[e.Name] || aliases[e.Name]
	case *syntax.DotExpr:
		return exprHoldsCapability(e.X, aliases)
	case *syntax.ParenExpr:
		return exprHoldsCapability(e.X, aliases)
	case *syntax.UnaryExpr:
		return e.X != nil && exprHoldsCapability(e.X, aliases)
	case *syntax.BinaryExpr:
		return exprHoldsCapability(e.X, aliases) || exprHoldsCapability(e.Y, aliases)
	case *syntax.IndexExpr:
		return exprHoldsCapability(e.X, aliases) || exprHoldsCapability(e.Y, aliases)
	case *syntax.ListExpr:
		for _, el := range e.List {
			if exprHoldsCapability(el, aliases) {
				return true
			}
		}
	case *syntax.TupleExpr:
		for _, el := range e.List {
			if exprHoldsCapability(el, aliases) {
				return true
			}
		}
	case *syntax.DictExpr:
		for _, el := range e.List {
			if entry, ok := el.(*syntax.DictEntry); ok {
				if exprHoldsCapability(entry.Key, aliases) || exprHoldsCapability(entry.Value, aliases) {
					return true
				}
			}
		}
	case *syntax.CondExpr:
		return exprHoldsCapability(e.True, aliases) || exprHoldsCapability(e.False, aliases)
	case *syntax.Comprehension:
		return exprHoldsCapability(e.Body, aliases)
	case *syntax.LambdaExpr:
		return exprHoldsCapability(e.Body, aliases)
	case *syntax.CallExpr:
		if dot, ok := e.Fn.(*syntax.DotExpr); ok {
			switch dot.Name.Name {
			case "read_classified", "map", "flat_map":
				return false // Classified data, not a capability
			case "access":
				return true // FileEntry is a capability handle
			}
		}
		// Unknown call: if the callee or any argument may hold a
		// capability, the result may capture it.
		if exprHoldsCapability(e.Fn, aliases) {
			return true
		}
		for _, arg := range e.Args {
			if exprHoldsCapability(arg, aliases) {
				return true
			}
		}
	}
	return false
}

// isGetattrCall reports whether call is an invocation of the getattr builtin.
func isGetattrCall(call *syntax.CallExpr) bool {
	id, ok := call.Fn.(*syntax.Ident)
	return ok && id.Name == "getattr"
}

// getattrStringArg returns the literal string attribute name when call is a
// getattr invocation whose second argument is a string literal.
func getattrStringArg(call *syntax.CallExpr) (string, bool) {
	if !isGetattrCall(call) || len(call.Args) < 2 {
		return "", false
	}
	lit, ok := call.Args[1].(*syntax.Literal)
	if !ok {
		return "", false
	}
	s, ok := lit.Value.(string)
	return s, ok
}
