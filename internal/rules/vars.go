package rules

import (
	"fmt"
	"slices"
	"strings"
)

// Rule file variables: "var NAME value" lines define an address or port
// value, used as $NAME in a rule's address and port fields and in other
// variables. Definitions may come in any order. A reference is replaced
// by the variable's text:
//
//   - $NAME as a whole field takes the value as is; !$NAME negates it
//     (a value that is already negated loses its '!').
//   - $NAME or !$NAME as a list item splices the value's items into the
//     list, negated for !$NAME. Only a value without any '!' and other
//     than any can be spliced: a negated value inside a list has no
//     meaning the list syntax can express.
//
// An undefined name, a redefinition and a reference cycle (including a
// variable that refers to itself) are errors.

// variable is one var line.
type variable struct {
	line  int
	raw   string // the value as written
	value string // raw with every reference expanded; valid when state == varDone and !bad
	addr  bool   // value is a valid address spec
	port  bool   // value is a valid port spec
	state uint8
	bad   bool  // the definition has an error
	err   error // the resolution error, reported on line
}

// cycleError is a reference cycle; it is passed up through every
// variable in the cycle.
type cycleError struct{ path string }

func (e *cycleError) Error() string { return "reference cycle " + e.path }

const (
	varNew uint8 = iota
	varResolving
	varDone
)

// varTable holds the variables of one rule file.
type varTable map[string]*variable

// isVarLine reports whether a non-comment line is a variable definition.
func isVarLine(line string) bool {
	f := strings.Fields(line)
	return len(f) > 0 && f[0] == "var"
}

// parseVars reads every var line, then resolves and checks each. It
// returns the table and the problems, keyed by line.
func parseVars(lines []srcLine) (varTable, []lineError) {
	vars := make(varTable)
	var errs []lineError
	for _, l := range lines {
		if !isVarLine(l.text) {
			continue
		}
		fail := func(format string, args ...any) {
			errs = append(errs, lineError{l.n, fmt.Sprintf(format, args...)})
		}
		rest := strings.TrimSpace(l.text[len("var"):])
		var name, value string
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			name, value = rest[:i], strings.TrimSpace(rest[i:])
		} else {
			name, value = rest, ""
		}
		if !isVarName(name) {
			fail("variable name %q: want a letter or '_', then letters, digits or '_'", name)
			continue
		}
		if old, dup := vars[name]; dup {
			fail("variable %s redefined (first defined on line %d)", name, old.line)
			continue
		}
		v := &variable{line: l.n}
		vars[name] = v
		fields, err := splitHeader(value)
		switch {
		case err != nil:
			fail("variable %s: %v", name, err)
			v.bad = true
		case len(fields) != 1:
			fail("variable %s: want one value (var NAME value), got %d fields", name, len(fields))
			v.bad = true
		default:
			v.raw = fields[0]
		}
	}
	// Resolve in line order, so cycle errors name the same path every run.
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int { return vars[a].line - vars[b].line })
	for _, name := range names {
		_ = vars.resolve(name, nil) // the error is kept in v.err
	}
	for _, name := range names {
		if v := vars[name]; v.err != nil {
			errs = append(errs, lineError{v.line, fmt.Sprintf("variable %s: %v", name, v.err)})
		}
	}
	return vars, errs
}

// resolve expands name's value, following references depth first. path
// is the chain of variables being resolved, for cycle errors. A variable
// whose resolution fails is marked bad and keeps its error in err.
func (vs varTable) resolve(name string, path []string) error {
	v := vs[name]
	switch {
	case v.bad:
		return fmt.Errorf("$%s is invalid (line %d)", name, v.line)
	case v.state == varDone:
		return nil
	case v.state == varResolving:
		return &cycleError{strings.Join(append(path, name), " -> ")}
	}
	v.state = varResolving
	value, err := vs.expand(v.raw, "", append(path, name))
	v.state = varDone
	if err == nil {
		_, aerr := parseAddrSpec(value)
		_, perr := parsePortSpec(value)
		v.value, v.addr, v.port = value, aerr == nil, perr == nil
		if !v.addr && !v.port {
			err = fmt.Errorf("%q is neither an address value (%v) nor a port value (%v)", value, aerr, perr)
		}
	}
	if err != nil {
		v.bad, v.err = true, err
	}
	return err
}

// expand replaces every $NAME reference in field. kind is "address" or
// "port" for a rule field, which each referenced variable must hold, or
// "" inside a variable's value. path is non-nil only inside resolve.
func (vs varTable) expand(field, kind string, path []string) (string, error) {
	if !strings.Contains(field, "$") {
		return field, nil
	}
	lookup := func(ref string) (string, error) {
		name := ref[1:]
		v, ok := vs[name]
		if !isVarName(name) {
			return "", fmt.Errorf("bad variable reference %q", ref)
		}
		if !ok {
			return "", fmt.Errorf("undefined variable %s", ref)
		}
		if path != nil {
			if err := vs.resolve(name, path); err != nil {
				if _, cyc := err.(*cycleError); cyc {
					return "", err
				}
				return "", fmt.Errorf("%s is invalid (line %d)", ref, v.line)
			}
		} else if v.bad || v.state != varDone {
			return "", fmt.Errorf("%s is invalid (line %d)", ref, v.line)
		}
		switch {
		case kind == "address" && !v.addr:
			return "", fmt.Errorf("%s holds ports, not addresses", ref)
		case kind == "port" && !v.port:
			return "", fmt.Errorf("%s holds addresses, not ports", ref)
		}
		return v.value, nil
	}

	neg, body := "", field
	if strings.HasPrefix(body, "!") {
		neg, body = "!", body[1:]
	}
	if strings.HasPrefix(body, "$") {
		val, err := lookup(body)
		if err != nil {
			return "", err
		}
		if neg != "" {
			if strings.HasPrefix(val, "!") {
				return val[1:], nil
			}
			return "!" + val, nil
		}
		return val, nil
	}
	if !strings.HasPrefix(body, "[") || !strings.HasSuffix(body, "]") || strings.Contains(body[1:len(body)-1], "[") {
		return "", fmt.Errorf("bad variable reference in %q: use $NAME as a whole field or list item", field)
	}
	items := strings.Split(body[1:len(body)-1], ",")
	var out []string
	for _, item := range items {
		ineg, ref := "", item
		if strings.HasPrefix(ref, "!") {
			ineg, ref = "!", ref[1:]
		}
		if !strings.HasPrefix(ref, "$") {
			if strings.Contains(ref, "$") {
				return "", fmt.Errorf("bad variable reference %q: use $NAME as a whole field or list item", item)
			}
			out = append(out, item)
			continue
		}
		val, err := lookup(ref)
		if err != nil {
			return "", err
		}
		if val == "any" || strings.Contains(val, "!") {
			return "", fmt.Errorf("%s cannot be used inside a list: its value %q is any or contains '!'", ref, val)
		}
		val = strings.TrimSuffix(strings.TrimPrefix(val, "["), "]")
		for _, x := range strings.Split(val, ",") {
			out = append(out, ineg+x)
		}
	}
	return neg + "[" + strings.Join(out, ",") + "]", nil
}

func isVarName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_'
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
