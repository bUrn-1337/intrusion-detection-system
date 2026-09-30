package rules

import (
	"fmt"
	"slices"
	"strings"
)

// Kill-chain stages come from "stage NAME CATEGORY[,CATEGORY...]"
// directives in the rule file. Their file order is the stage order, which
// incident rules (correlate.go) require a chain to follow. An alert's
// stage is the stage its rule's category maps to; a category no directive
// lists maps to no stage.

// maxStages bounds the number of stage directives (a stageSet is a bit
// set).
const maxStages = 16

// stageSet is a set of stage indexes.
type stageSet uint16

func (s stageSet) has(i int) bool { return i >= 0 && s&(1<<i) != 0 }

// count returns the number of stages in s.
func (s stageSet) count() int {
	n := 0
	for ; s != 0; s &= s - 1 {
		n++
	}
	return n
}

// standardCategories are the categories of the shipped rules. A stage
// directive may name these or any category a rule in the file uses.
var standardCategories = []string{"recon", "web", "web-attack", "evasion", "credential", "malware", "threat-intel",
	"exfiltration", "dos", "spoofing", "anomaly", "policy", "dns", "incident"}

// stageTable is the parsed stage directives.
type stageTable struct {
	names   []string       // in order
	of      map[string]int // category -> stage index
	catLine map[string]int // category -> the line of its directive, for errors
	lines   []int          // the line of each directive
}

func newStageTable() *stageTable {
	return &stageTable{of: make(map[string]int), catLine: make(map[string]int)}
}

// stage returns the stage index of a category, or -1.
func (st *stageTable) stage(category string) int {
	if i, ok := st.of[category]; ok {
		return i
	}
	return -1
}

// index returns the stage index of a stage name, or -1.
func (st *stageTable) index(name string) int {
	return slices.Index(st.names, name)
}

// parseStageList parses a from/to option value: stage names separated by
// commas, all defined by stage directives.
func (st *stageTable) parseStageList(v string) (stageSet, error) {
	var s stageSet
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		i := st.index(name)
		if i < 0 {
			if len(st.names) == 0 {
				return 0, fmt.Errorf("stage %q: the file has no stage directives", name)
			}
			return 0, fmt.Errorf("unknown stage %q (stages: %s)", name, strings.Join(st.names, ", "))
		}
		if s.has(i) {
			return 0, fmt.Errorf("stage %s listed twice", name)
		}
		s |= 1 << i
	}
	return s, nil
}

// names of the stages in s, in stage order.
func (st *stageTable) setNames(s stageSet) []string {
	var out []string
	for i, n := range st.names {
		if s.has(i) {
			out = append(out, n)
		}
	}
	return out
}

func isStageLine(line string) bool {
	f := strings.Fields(line)
	return len(f) > 0 && f[0] == "stage"
}

// parseStages reads every "stage NAME CATEGORY[,CATEGORY...]" line.
// Category names are checked later, by checkStageCategories, once the
// rules' categories are known.
func parseStages(lines []srcLine) (*stageTable, []lineError) {
	st := newStageTable()
	var errs []lineError
	nameLine := make(map[string]int)
	for _, l := range lines {
		if !isStageLine(l.text) {
			continue
		}
		fail := func(format string, args ...any) {
			errs = append(errs, lineError{l.n, fmt.Sprintf(format, args...)})
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "stage"))
		name, cats, ok := strings.Cut(rest, " ")
		cats = strings.TrimSpace(cats)
		if !ok || name == "" || cats == "" {
			fail("stage: want \"stage NAME CATEGORY[,CATEGORY...]\"")
			continue
		}
		if !isName(name) {
			fail("stage name %q: want letters, digits, '_' or '-'", name)
			continue
		}
		if first, dup := nameLine[name]; dup {
			fail("stage %s defined twice (first on line %d)", name, first)
			continue
		}
		if len(st.names) == maxStages {
			fail("more than %d stages", maxStages)
			continue
		}
		idx := len(st.names)
		var list []string
		bad := false
		for _, c := range strings.Split(cats, ",") {
			c = strings.TrimSpace(c)
			switch {
			case !isName(c):
				fail("stage %s: category %q: want letters, digits, '_' or '-'", name, c)
				bad = true
			case slices.Contains(list, c):
				fail("stage %s: category %s listed twice", name, c)
				bad = true
			default:
				if first, dup := st.catLine[c]; dup {
					fail("stage %s: category %s is already mapped to stage %s (line %d)", name, c, st.names[st.of[c]], first)
					bad = true
					continue
				}
				list = append(list, c)
			}
		}
		if bad {
			continue
		}
		nameLine[name] = l.n
		st.names = append(st.names, name)
		st.lines = append(st.lines, l.n)
		for _, c := range list {
			st.of[c], st.catLine[c] = idx, l.n
		}
	}
	return st, errs
}

// checkStageCategories reports stage categories that are neither standard
// nor used by a rule: most likely a typo, which would silently map
// nothing.
func (st *stageTable) checkStageCategories(rules []*Rule) []lineError {
	used := make(map[string]bool)
	for _, r := range rules {
		used[r.Category] = true
	}
	var errs []lineError
	for c, line := range st.catLine {
		if !used[c] && !slices.Contains(standardCategories, c) {
			errs = append(errs, lineError{line, fmt.Sprintf("stage %s: unknown category %q (not a standard category or one a rule uses)", st.names[st.of[c]], c)})
		}
	}
	return errs
}
