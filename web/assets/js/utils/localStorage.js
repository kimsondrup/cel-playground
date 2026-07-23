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

import {
  localStorageModeKey,
  localStorageThemeKey,
  localStorageWarningsOpenKey,
} from "../constants.js";

export function getCurrentTheme() {
  return localStorage.getItem(localStorageThemeKey) ?? "light";
}

export function getCurrentMode() {
  return localStorage.getItem(localStorageModeKey) ?? "cel";
}

// Warnings open expanded, since they describe something that already affected
// the result. Once someone has collapsed one they have read it, and a warning
// that reappears expanded on every run is just something to close again -- so
// the last state they chose is what the next run starts in.
export function getWarningsOpen() {
  return localStorage.getItem(localStorageWarningsOpenKey) !== "false";
}

export function setWarningsOpen(isOpen) {
  localStorage.setItem(localStorageWarningsOpenKey, String(isOpen));
}
