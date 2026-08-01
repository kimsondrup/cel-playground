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
import {
  COPY_FEEDBACK_MS,
  copyToClipboard,
} from "../../utils/clipboard.js";
import { getWarningsOpen, setWarningsOpen } from "../../utils/localStorage.js";

const outputResultEl = document.getElementById("editor__output-result");
// Numbers the section bodies so each header can name the one it controls.
let sectionCount = 0;
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

// isPlainResult is true for the sections that arrive as bare strings -- the
// diff, the final object, the not-simulated note and each warning -- rather
// than as result objects with a cost and an error.
function isPlainResult(result) {
  return typeof result !== "object" || result === null;
}

// renderDiff colorizes a unified diff. The result panel background is always
// dark, so the colors are picked for a dark background.
function renderDiff(diff) {
  const lines = escapeHtml(diff.trimEnd())
    .split("\n")
    .map((line, i) => {
      // Only the first two lines are the --- / +++ file headers. A removed line
      // whose own text starts with -- would otherwise be read as one.
      if (i < 2 && (line.startsWith("---") || line.startsWith("+++")))
        return `<span class="diff-file">${line}</span>`;
      if (line.startsWith("@@")) return `<span class="diff-hunk">${line}</span>`;
      if (line.startsWith("+")) return `<span class="diff-add">${line}</span>`;
      if (line.startsWith("-")) return `<span class="diff-del">${line}</span>`;
      return line;
    });
  return `<pre>${lines.join("\n")}</pre>`;
}

// errorTooltips says what failed, per section kind. A mutation can fail at
// compilation, at evaluation, at patching or because there is nothing to
// mutate, so the generic wording is the fallback rather than the rule.
const errorTooltips = {
  mutations: "This mutation was not applied.",
  mutationVariables: "This variable could not be evaluated.",
  matchConditions: "This match condition could not be evaluated.",
  webhookMatchConditions: "This match condition could not be evaluated.",
  validations: "This validation could not be evaluated.",
  messageExpressions: "This message expression could not be evaluated.",
  auditAnnotations: "This audit annotation could not be evaluated.",
  validationVariables: "This variable could not be evaluated.",
  messageExpressionVariables: "This variable could not be evaluated.",
  auditAnnotationVariables: "This variable could not be evaluated.",
};

// sectionLabel names a result section, for the row and for the copy button's
// accessible name.
function sectionLabel(item, name, i, total) {
  // A bare string is its own label: "finalObject[0]" would be misleading.
  // warnings is the one list of them, and an index only helps once there is
  // more than one to tell apart.
  if (isPlainResult(item)) return total > 1 ? `${name}[${i}]` : name;
  // item.name is a validation or variable name straight out of the policy.
  if (item.name) return `${name}.${item.name}`;
  // A mutation has no name; its patch type is what distinguishes it.
  if (item.patchType) return `${name}[${i}] (${item.patchType})`;
  return `${name}[${i}]`;
}

// aria-label wins the accessible-name computation over title, so both have to
// move together or the icon swap stays visual-only.
function setCopyLabel(button, label) {
  button.title = label;
  button.setAttribute("aria-label", label);
}

function createCopyButton(text, label) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "result-accordion-copy";

  const icon = document.createElement("i");
  icon.className = "ph ph-copy";
  button.appendChild(icon);

  // Every section renders one of these, so an undifferentiated "Copy to
  // clipboard" repeated N times is not navigable.
  const idleLabel = label ? `Copy ${label}` : "Copy to clipboard";
  setCopyLabel(button, idleLabel);

  let resetTimer;
  const showFeedback = (copied) => {
    icon.className = copied ? "ph ph-check" : "ph ph-x";
    button.classList.toggle("copied", copied);
    button.classList.toggle("copy-failed", !copied);
    setCopyLabel(button, copied ? "Copied" : "Could not copy");

    window.clearTimeout(resetTimer);
    resetTimer = window.setTimeout(() => {
      icon.className = "ph ph-copy";
      button.classList.remove("copied", "copy-failed");
      setCopyLabel(button, idleLabel);
    }, COPY_FEEDBACK_MS);
  };

  button.onclick = (event) => {
    // The whole row toggles the accordion, so copying must not also collapse
    // the section the user is reading.
    event.stopPropagation();
    copyToClipboard(text).then(showFeedback);
  };

  return button;
}

function createAccordionItemsByResults(name, result, index, total = 1) {
  const isWarning = name === "warnings";

  const listItem = document.createElement("li");
  listItem.className = "editor__output-result-accordion";
  // The decision, the warnings and the diff start expanded: the decision is the
  // answer, a warning describes something that already affected it, and the
  // diff is what the policy did. A collapsed warning stays collapsed -- see
  // getWarningsOpen.
  const startsOpen = isWarning
    ? getWarningsOpen()
    : name === "diff" || name === "decision";
  listItem.setAttribute("data-open", startsOpen ? "true" : "false");

  const toggle = () => {
    const isAccordionOpen = listItem.getAttribute("data-open") === "true";
    listItem.setAttribute("data-open", isAccordionOpen ? "false" : "true");
    accordionContent.setAttribute("aria-expanded", String(!isAccordionOpen));
    if (isWarning) setWarningsOpen(!isAccordionOpen);
  };

  const accordionContent = document.createElement("div");
  accordionContent.className = "result-accordion-content";
  // The header row is the control, so it is the thing that takes focus and
  // answers the keyboard. Only it toggles: the body is there to be read from,
  // and ending a selection inside it must not collapse the section -- which for
  // a warning would also switch off the remembered preference.
  accordionContent.setAttribute("role", "button");
  accordionContent.setAttribute("tabindex", "0");
  accordionContent.setAttribute("aria-expanded", String(startsOpen));
  accordionContent.onclick = (e) => {
    // The copy button is inside the header and has its own action.
    if (e.target.closest(".result-accordion-copy")) return;
    toggle();
  };
  accordionContent.onkeydown = (e) => {
    if (e.key !== "Enter" && e.key !== " " && e.key !== "Spacebar") return;
    e.preventDefault();
    toggle();
  };
  accordionContent.appendChild(createLabel(result, name, index, total));
  // The cost and the copy button share a right-hand group, so the label still
  // sits opposite them under the row's space-between.
  const actions = document.createElement("div");
  actions.className = "result-accordion-actions";
  // A bare string has no cost of its own, and neither has the decision: it is
  // the conclusion the costs above it add up to, not an expression.
  if (!isPlainResult(result) && name !== "decision") {
    const costSpan = document.createElement("span");
    costSpan.innerHTML = `Cost: ${result?.cost ?? "-"}`;
    actions.appendChild(costSpan);
  }
  const { text, html } = renderResult(result, name);
  if (text !== "") {
    const label = sectionLabel(result, name, index, total);
    actions.appendChild(createCopyButton(text, label));
  }
  accordionContent.appendChild(actions);

  const expansibleContent = document.createElement("div");
  expansibleContent.className = "result-accordion-expansible-content";
  expansibleContent.id = `result-body-${sectionCount++}`;
  accordionContent.setAttribute("aria-controls", expansibleContent.id);
  // No wrapper element: most bodies are a <pre> or a <p>, and nesting a block
  // inside an inline <span> makes the browser split it into anonymous blocks.
  expansibleContent.innerHTML = html;

  listItem.appendChild(accordionContent);
  listItem.appendChild(expansibleContent);

  outputResultEl.appendChild(listItem);
}
// renderResult produces both forms of a section body from one branch structure:
// the markup for the panel, and the plain text the copy button puts on the
// clipboard. They cannot drift apart while they are built together.
//
// text is "" wherever the markup is a placeholder describing the value rather
// than being it, and no copy button is offered for those.
function renderResult(result, name) {
  if (isPlainResult(result)) {
    const text = String(result);
    if (name === "diff") return { text, html: renderDiff(result) };
    // Warnings and the not-simulated note are prose, not documents: <pre> would
    // send a full sentence off the right edge behind a horizontal scrollbar.
    if (name === "warnings" || name === "notSimulated") {
      const style = name === "warnings" ? "result-warning" : "result-note";
      return { text, html: `<p class="${style}">${escapeHtml(text)}</p>` };
    }
    // YAML ends with a newline, which <pre> would render as a blank last line.
    return { text, html: `<pre>${escapeHtml(text.trimEnd())}</pre>` };
  }

  if (result.isError) {
    const text = result.error == null ? "" : String(result.error);
    return {
      text,
      html: `<span class="result-error">${escapeHtml(text)}</span>`,
    };
  }
  if ("mutatedObject" in result) {
    const text = String(result.mutatedObject);
    return { text, html: `<pre>${escapeHtml(text.trimEnd())}</pre>` };
  }
  if ("message" in result) return renderText(result.message);
  if ("value" in result) {
    if (typeof result.value === "object") {
      const text = JSON.stringify(result.value, null, 2);
      return { text, html: `<pre>${escapeHtml(text)}</pre>` };
    }
    return renderText(result.value);
  }

  // omitempty drops the key entirely when the expression yielded nothing.
  if (result.result === undefined) {
    return { text: "", html: `<span class="result-empty">(no value)</span>` };
  }
  return renderText(result.result);
}

// An expression can legitimately produce nothing to print, and an open section
// with an empty body reads as a broken panel rather than as a result. The two
// ways of producing nothing stay separate placeholders: optional.none() and an
// expression returning "" are different outcomes.
function renderText(value) {
  const text = String(value);
  if (text === "") {
    return { text, html: `<span class="result-empty">(empty string)</span>` };
  }
  return { text, html: escapeHtml(text) };
}

function createLabel(item, name, i, total = 1) {
  const parentContainer = document.createElement("div");
  parentContainer.className = "result-accordion-label";

  const arrowIcon = document.createElement("i");
  arrowIcon.className = "ph ph-caret-right ph-bold result-arrow";

  const span = document.createElement("span");
  span.innerHTML = escapeHtml(sectionLabel(item, name, i, total));

  parentContainer.appendChild(arrowIcon);

  if (name === "warnings") {
    const warningIcon = document.createElement("i");
    warningIcon.className = "ph ph-warning ph-fill result-accordion-warning-icon";
    warningIcon.setAttribute("aria-hidden", "true");
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
    errorIcon.className = "ph ph-x-circle ph-fill result-accordion-error-icon";
    errorIcon.setAttribute("aria-hidden", "true");

    const errorIconWithTooltip = createTooltip({
      contentText:
        errorTooltips[name] ??
        "This entry reported an error. Expand it to read the message.",
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

  Object.entries(result).forEach(([key, values]) => {
    renderAccordions(key, values);
  });
}
