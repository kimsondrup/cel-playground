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

// unifiedDiff renders a unified diff of two YAML documents, with the usual
// three lines of context. It returns an empty string when the documents are
// identical.
//
// go-udiff is the diff gopls uses, ported out of x/tools. It matters here that
// it is Myers rather than a full LCS table: the playground diffs an object
// against its mutated self, and two edits at opposite ends of a large object
// are cheap for Myers and quadratic in the distance between them for a table.
func unifiedDiff(from, to, fromLabel, toLabel string) string {
	return udiff.Unified(fromLabel, toLabel, from, to)
}
