// Copyright 2025 Undistro Authors
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

import "github.com/aymanbagabas/go-udiff"

// diffContextLines is how many unchanged lines are shown around each change.
//
// More than a source diff shows, because a YAML object gives a line almost no
// context of its own: three lines above `cpu: "2"` is still inside the same
// resources block, and the container it belongs to is further up than that.
const diffContextLines = 8

// unifiedDiff renders a unified diff of two YAML documents. It returns an empty
// string when the documents are identical.
//
// go-udiff is the diff gopls uses, ported out of x/tools. It matters here that
// it is Myers rather than a full LCS table: the playground diffs an object
// against its mutated self, and two edits at opposite ends of a large object
// are cheap for Myers and quadratic in the distance between them for a table.
func unifiedDiff(from, to, fromLabel, toLabel string) string {
	// Lines, not Strings: line-granularity edits, so a changed line is one
	// removal and one addition rather than an edit within the line.
	edits := udiff.Lines(from, to)
	rendered, err := udiff.ToUnified(fromLabel, toLabel, from, edits, diffContextLines)
	if err != nil {
		// Only returned for edits that do not apply to the content they were
		// computed from, which cannot happen when both come from here.
		return ""
	}
	return rendered
}
