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

// diffOps produces the edit script via the classic LCS dynamic program.
//
// The two inputs are serializations of the same object, so they normally share
// a long identical prefix and suffix. Those are matched off first and only the
// window between them reaches the O(n*m) table, which is what keeps the table
// proportional to the change rather than to the document: inserting one line
// into a 5000-line object allocates ~0.4 MB this way instead of ~200 MB. A
// leading or trailing line that is equal in both documents can always be
// matched by some optimal alignment, so trimming does not lengthen the edit
// script.
func diffOps(from, to []string) []diffOp {
	prefix := 0
	for prefix < len(from) && prefix < len(to) && from[prefix] == to[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(from)-prefix && suffix < len(to)-prefix &&
		from[len(from)-1-suffix] == to[len(to)-1-suffix] {
		suffix++
	}

	// The trimmed lines are still emitted as context ops, so groupHunks sees a
	// complete line-by-line script and the @@ headers stay absolute.
	ops := make([]diffOp, 0, len(from)+len(to))
	for i := 0; i < prefix; i++ {
		ops = append(ops, diffOp{' ', from[i], i, i})
	}
	ops = append(ops, diffWindow(from[prefix:len(from)-suffix], to[prefix:len(to)-suffix], prefix)...)
	for i := 0; i < suffix; i++ {
		fromLine := len(from) - suffix + i
		toLine := len(to) - suffix + i
		ops = append(ops, diffOp{' ', from[fromLine], fromLine, toLine})
	}
	return ops
}

// diffWindow runs the LCS dynamic program over the changed window. offset is
// the number of lines trimmed off the front of both documents, added back so
// the reported line numbers stay absolute.
func diffWindow(from, to []string, offset int) []diffOp {
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
			ops = append(ops, diffOp{' ', from[i], i + offset, j + offset})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{'-', from[i], i + offset, j + offset})
			i++
		default:
			ops = append(ops, diffOp{'+', to[j], i + offset, j + offset})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', from[i], i + offset, j + offset})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', to[j], i + offset, j + offset})
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
