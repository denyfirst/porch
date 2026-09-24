/*
  The colour scheme switch, and nothing else.

  Loaded in the head of every page, before anything is drawn, so a reader who
  chose a scheme is never shown the other one first. The page follows the
  system until the switch is used; then it remembers "light" or "dark" in this
  browser's local storage, which is the one thing any page here stores. It is
  never sent anywhere: the server does not read it and nothing in it names a
  person or a host.

  No markup is built here and nothing a server sends is read, which is why this
  is a file of its own rather than part of app.js: a page that runs no check
  loads this and nothing else.
*/

"use strict";

(function () {
  const KEY = "theme";
  const root = document.documentElement;

  function stored() {
    try {
      const value = window.localStorage.getItem(KEY);
      return value === "light" || value === "dark" ? value : null;
    } catch {
      // Storage refused (a private window, a policy). The system decides.
      return null;
    }
  }

  function current() {
    const chosen = stored();
    if (chosen) return chosen;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  const initial = stored();
  if (initial) root.dataset.theme = initial;

  /*
    The mark says what pressing it does, not what is showing: a sun to go to
    the light scheme, a moon to go to the dark one.

    Drawn rather than written, and drawn here rather than shipped as a file: two
    paths of geometry cost less than a request, carry the current colour on
    their own, and cannot go missing. The word stays in aria-label, which is
    what a screen reader announces and what a test can read — an icon with no
    name is a button nobody can describe.
  */
  // A circle split down the middle, one half filled. The filled half is the
  // scheme pressing it gives you, so the fill moves across as you switch.
  //
  // Geometry rather than a sun and a moon: it is the same figure the icon of
  // this site is built from — a shape cut by a straight line — and at eighteen
  // pixels a circle half in shadow is read instantly, while a sun with eight
  // rays is a smudge.
  const TO_DARK = "M12 4a8 8 0 0 1 0 16Z";
  const TO_LIGHT = "M12 4a8 8 0 0 0 0 16Z";

  function label(button) {
    const toLight = current() === "dark";
    button.setAttribute("aria-label",
      toLight ? "Switch to the light colour scheme" : "Switch to the dark colour scheme");

    while (button.firstChild) button.removeChild(button.firstChild);

    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");

    const ring = document.createElementNS(ns, "circle");
    ring.setAttribute("cx", "12");
    ring.setAttribute("cy", "12");
    ring.setAttribute("r", "8");
    svg.appendChild(ring);

    const half = document.createElementNS(ns, "path");
    half.setAttribute("d", toLight ? TO_LIGHT : TO_DARK);
    half.setAttribute("class", "theme-half");
    svg.appendChild(half);

    button.appendChild(svg);
  }

  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    button.hidden = false;
    label(button);

    button.addEventListener("click", () => {
      const next = current() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        window.localStorage.setItem(KEY, next);
      } catch {
        // Not remembered, and still switched for this page.
      }
      label(button);
    });
  });
})();
