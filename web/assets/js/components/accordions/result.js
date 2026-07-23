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

import { createTooltip } from "../tooltips/index.js";
import { getWarningsOpen, setWarningsOpen } from "../../utils/localStorage.js";

const outputResultEl = document.getElementById("editor__output-result");
const holderEl = document.querySelector(".editor__output-holder");

// Everything the evaluator returns is built from what the user typed -- CEL
// errors quote the source expression verbatim, and messageExpression results
// are whatever string the policy produced. It all reaches innerHTML below, and
// share.js encodes the editor state into a link, so it must be escaped.
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// isPlainResult is true for top-level result fields that are bare strings
// (the Mutating Admission Policy `finalObject` and `diff`) rather than result
// objects.
function isPlainResult(result) {
  return typeof result !== "object" || result === null;
}

// renderDiff colorizes a unified diff. The result panel background is always
// dark, so the colors are picked for a dark background.
function renderDiff(diff) {
  const lines = escapeHtml(diff)
    .split("\n")
    .map((line) => {
      // The leading --- / +++ file headers are not deletions and additions.
      if (line.startsWith("---") || line.startsWith("+++"))
        return `<span class="diff-file">${line}</span>`;
      if (line.startsWith("@@")) return `<span class="diff-hunk">${line}</span>`;
      if (line.startsWith("+")) return `<span class="diff-add">${line}</span>`;
      if (line.startsWith("-")) return `<span class="diff-del">${line}</span>`;
      return line;
    });
  return `<pre>${lines.join("\n")}</pre>`;
}

const COPY_FEEDBACK_MS = 1200;

// getResultText is the plain-text twin of getResultValue: same content, without
// the markup. Keep the two in step, since this is what the copy button puts on
// the clipboard and a user comparing them will notice any divergence.
function getResultText(result) {
  if (isPlainResult(result)) return result == null ? "" : String(result);
  if (result.isError) return result.error == null ? "" : String(result.error);
  if ("mutatedObject" in result) return String(result.mutatedObject);
  if ("message" in result) return String(result.message);
  if ("value" in result) {
    if (typeof result.value === "object" && result.value !== null)
      return JSON.stringify(result.value, null, 2);
    return String(result.value);
  }
  return result.result === undefined ? "" : String(result.result);
}

// document.execCommand is deprecated, but navigator.clipboard only exists in a
// secure context and a locally served copy of the playground is easily not one.
function copyWithExecCommand(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();

  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (error) {
    console.error("failed to copy to the clipboard", error);
  }
  document.body.removeChild(textarea);
  return copied;
}

async function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      console.error("failed to copy to the clipboard", error);
    }
  }
  return copyWithExecCommand(text);
}

function showCopyFeedback(button, copied) {
  const icon = button.querySelector("i");
  icon.className = copied ? "ph ph-check" : "ph ph-x";
  button.classList.toggle("copied", copied);
  button.classList.toggle("copy-failed", !copied);
  button.title = copied ? "Copied" : "Could not copy";

  window.clearTimeout(button.resetTimer);
  button.resetTimer = window.setTimeout(() => {
    icon.className = "ph ph-copy";
    button.classList.remove("copied", "copy-failed");
    button.title = "Copy to clipboard";
  }, COPY_FEEDBACK_MS);
}

function createCopyButton(text) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "result-accordion-copy";
  button.title = "Copy to clipboard";
  button.setAttribute("aria-label", "Copy to clipboard");
  button.innerHTML = `<i class="ph ph-copy"></i>`;

  button.onclick = (event) => {
    // The whole row toggles the accordion, so copying must not also collapse
    // the section the user is reading.
    event.stopPropagation();
    copyToClipboard(text).then((copied) => showCopyFeedback(button, copied));
  };

  return button;
}

function createAccordionItemsByResults(name, result, index, total = 1) {
  const isWarning = name === "warnings";

  const listItem = document.createElement("li");
  listItem.className = "editor__output-result-accordion";
  // Warnings are the only section that starts expanded, and only until the
  // reader collapses one. See getWarningsOpen.
  listItem.setAttribute(
    "data-open",
    isWarning && getWarningsOpen() ? "true" : "false"
  );
  listItem.onclick = (e) => {
    const isAccordionOpen = listItem.getAttribute("data-open") === "true";
    listItem.setAttribute("data-open", isAccordionOpen ? "false" : "true");
    if (isWarning) setWarningsOpen(!isAccordionOpen);
  };

  const accordionContent = document.createElement("div");
  accordionContent.className = "result-accordion-content";
  accordionContent.appendChild(createLabel(result, name, index, total));

  // The cost and the copy button share a right-hand group, so the label still
  // sits opposite them under the row's space-between.
  const actions = document.createElement("div");
  actions.className = "result-accordion-actions";
  if (!isPlainResult(result)) {
    const costSpan = document.createElement("span");
    costSpan.innerHTML = `Cost: ${result?.cost ?? "-"}`;
    actions.appendChild(costSpan);
  }
  const textToCopy = getResultText(result);
  if (textToCopy !== "") actions.appendChild(createCopyButton(textToCopy));
  accordionContent.appendChild(actions);

  const expansibleContent = document.createElement("div");
  expansibleContent.className = "result-accordion-expansible-content";
  expansibleContent.innerHTML = `<span>${getResultValue(result, name)}</span>`;

  listItem.appendChild(accordionContent);
  listItem.appendChild(expansibleContent);

  outputResultEl.appendChild(listItem);
}
function getResultValue(result, name) {
  if (isPlainResult(result)) {
    if (name === "diff") return renderDiff(result);
    // Warnings are prose, not a document: <pre> would send a full sentence off
    // the right edge behind a horizontal scrollbar.
    if (name === "warnings")
      return `<p class="result-warning">${escapeHtml(result)}</p>`;
    return `<pre>${escapeHtml(result)}</pre>`;
  }

  if (result.isError) {
    return `<span style="color:#e01e5a">${escapeHtml(result.error)}</span>`;
  } else if ("mutatedObject" in result) {
    return `<pre>${escapeHtml(result.mutatedObject)}</pre>`;
  } else if ("message" in result) {
    return escapeHtml(result.message);
  } else if ("value" in result) {
    if (typeof result.value === "object")
      return `<pre>${escapeHtml(JSON.stringify(result.value, null, 2))}</pre>`;
    return escapeHtml(result.value);
  }

  return escapeHtml(result.result);
}

function createLabelText(item, name, i, total) {
  // `finalObject` and `diff` are single string values, so they are their own
  // label -- "finalObject[0]" would be misleading. A list of them still needs
  // indexing to tell the entries apart.
  if (isPlainResult(item)) return total > 1 ? `${name}[${i}]` : name;
  if (item.name) return `${name}.${item.name}`;
  // Mutations have no name; the patch type is what distinguishes them.
  if (item.patchType) return `${name}[${i}] (${item.patchType})`;
  return `${name}[${i}]`;
}

function createLabel(item, name, i, total = 1) {
  const parentContainer = document.createElement("div");
  parentContainer.style =
    "display: flex; align-items: center; gap: 0.5rem; position:relative";

  const arrowIcon = document.createElement("i");
  arrowIcon.className = "ph ph-caret-right ph-bold result-arrow";

  const span = document.createElement("span");
  span.innerHTML = escapeHtml(createLabelText(item, name, i, total));

  parentContainer.appendChild(arrowIcon);

  if (name === "warnings") {
    const warningIcon = document.createElement("i");
    warningIcon.className =
      "ph ph-warning ph-fill result-accordion-warning-icon";
    parentContainer.appendChild(
      createTooltip({
        contentText: "The result may not match a real cluster.",
        triggerElement: warningIcon,
        position: { left: 50, top: -10 },
      })
    );
  }

  if (item?.isError) {
    const errorIcon = document.createElement("i");
    errorIcon.className = "ph ph-x-circle ph-fill";
    errorIcon.style =
      "color: #e01e5a; z-index:999999; display:flex;align-items:center;justify-content: center;";

    const errorIconWithTooltip = createTooltip({
      contentText:
        name === "mutations"
          ? "Mutation compilation failed."
          : "Validation compilation failed.",
      triggerElement: errorIcon,
      position: {
        left: 50,
        top: -10,
      },
    });
    parentContainer.appendChild(errorIconWithTooltip);
  }

  parentContainer.appendChild(span);

  return parentContainer;
}

function renderAccordions(key, values, index = 0, total = 1) {
  if (Array.isArray(values))
    values.forEach((value, i) => renderAccordions(key, value, i, values.length));
  else createAccordionItemsByResults(key, values, index, total);
}

export function hideAccordions() {
  outputResultEl.style.display = "none";
  holderEl.scrollTo({ top: 0, behavior: "smooth" });
}

export function handleRenderAccordions(result) {
  outputResultEl.innerHTML = "";
  outputResultEl.style.display = "flex";

  holderEl.scrollTo({ top: 0, behavior: "smooth" });
  holderEl.style.overflowY = "auto";
  holderEl.style.overflowX = "hidden";

  Object.entries(result).forEach(([key, values]) => {
    renderAccordions(key, values);
  });
}
