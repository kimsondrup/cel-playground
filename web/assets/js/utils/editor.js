/**
 * Copyright 2024 Undistro Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AceEditor } from "../editor.js";
import { setEditorTheme } from "../theme.js";
import { getCurrentMode } from "./localStorage.js";

// The expression editor's DOM id is rewritten to the mode id on every mode
// switch (see renderExpressionContent). Looking it up by its stable class
// instead of by the current mode means a mode/DOM disagreement can no longer
// crash with ace's "can't find div #<mode>".
function exprEditorId() {
  const exprInput = document.querySelector(".editor__input.expr__input");
  if (!exprInput) throw new Error("the expression editor is not rendered yet");
  return exprInput.id;
}

export function getExprEditorValue() {
  const exprEditor = new AceEditor(exprEditorId());
  const exprEditorValue = exprEditor.getValue();
  setEditorTheme(exprEditor);
  return exprEditorValue;
}

export function getInputEditorValue() {
  const editorsInputEl = document.querySelectorAll(
    ".editor__input.data__input"
  );
  const tabsEL = document.getElementById("tabs");
  const currentTabActiveIndex = Number(tabsEL.getAttribute("data-tab-active"));
  const editor = editorsInputEl[currentTabActiveIndex];
  const inputEditor = new AceEditor(editor.id);
  setEditorTheme(inputEditor);
  return inputEditor.getValue();
}

export function getRunValues() {
  const modeId = getCurrentMode();
  const exprEditor = new AceEditor(exprEditorId());
  setEditorTheme(exprEditor);
  // Keyed by the mode id, which is what the wasm side reads with getArg.
  let values = {
    [modeId]: exprEditor.getValue(),
  };

  document.querySelectorAll(".editor__input.data__input").forEach((editor) => {
    const containerId = editor.id;
    const dataEditor = new AceEditor(containerId);
    setEditorTheme(dataEditor);
    values = {
      ...values,
      [containerId]: dataEditor.getValue(),
    };
  });

  return values;
}
