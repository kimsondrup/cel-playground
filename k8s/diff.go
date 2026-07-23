// Copyright 2023 Undistro Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"fmt"
	"strings"
)

// diffContextLines is the number of unchanged lines shown around each hunk.
const diffContextLines = 3

// unifiedDiff renders a unified diff of two YAML documents. It returns an empty
// string when the documents are identical.
//
// This is deliberately a small self-contained implementation: the playground
// ships as a wasm binary, so pulling a diff library in for one summary panel is
// not worth the bytes.
func unifiedDiff(from, to, fromLabel, toLabel string) string {
	if from == to {
		return ""
	}
	fromLines := splitLines(from)
	toLines := splitLines(to)

	ops := diffOps(fromLines, toLines)
	hunks := groupHunks(ops)
	if len(hunks) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n", fromLabel)
	fmt.Fprintf(&b, "+++ %s\n", toLabel)
	for _, hunk := range hunks {
		fromCount, toCount := 0, 0
		for _, op := range hunk {
			if op.kind != '+' {
				fromCount++
			}
			if op.kind != '-' {
				toCount++
			}
		}
		// A zero-length side starts at line 0, not 1, per the unified diff
		// format, so the output can be fed to patch(1).
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n",
			hunkStart(hunk[0].fromLine, fromCount), fromCount,
			hunkStart(hunk[0].toLine, toCount), toCount)
		for _, op := range hunk {
			b.WriteByte(op.kind)
			b.WriteString(op.text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func hunkStart(line, count int) int {
	if count == 0 {
		return line
	}
	return line + 1
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// diffOp is one line of the diff: kind is ' ' (context), '-' (removed) or '+'
// (added). fromLine/toLine are the 0-based line numbers the op starts at in
// each document, used to build the @@ hunk headers.
type diffOp struct {
	kind     byte
	text     string
	fromLine int
	toLine   int
}

// diffOps produces the edit script via the classic LCS dynamic program. The
// inputs are two serializations of the same object, so they are small and
// mostly identical; an O(n*m) table is fine here.
func diffOps(from, to []string) []diffOp {
	n, m := len(from), len(to)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if from[i] == to[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case from[i] == to[j]:
			ops = append(ops, diffOp{' ', from[i], i, j})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{'-', from[i], i, j})
			i++
		default:
			ops = append(ops, diffOp{'+', to[j], i, j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', from[i], i, j})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', to[j], i, j})
	}
	return ops
}

// groupHunks keeps only the changed ops plus diffContextLines of surrounding
// context, splitting the result into contiguous hunks.
func groupHunks(ops []diffOp) [][]diffOp {
	keep := make([]bool, len(ops))
	changed := false
	for i, op := range ops {
		if op.kind == ' ' {
			continue
		}
		changed = true
		for j := max(0, i-diffContextLines); j <= min(len(ops)-1, i+diffContextLines); j++ {
			keep[j] = true
		}
	}
	if !changed {
		return nil
	}

	var hunks [][]diffOp
	var current []diffOp
	for i, op := range ops {
		if !keep[i] {
			if len(current) > 0 {
				hunks = append(hunks, current)
				current = nil
			}
			continue
		}
		current = append(current, op)
	}
	if len(current) > 0 {
		hunks = append(hunks, current)
	}
	return hunks
}
