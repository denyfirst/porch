/*
  Signing in, signing out, changing the password and the second factor, and
  the Copy beside the sign-in page's one command. Nothing else.

  A file of its own because the pages that need it are every page behind a
  password, and most of them load no other script: History in particular
  serves no result and runs nothing that could fetch one. This asks the
  session endpoints and moves the browser; it reads no report and stores
  nothing. The session itself is a cookie the server sets, which no script
  here can read.

  Every form gets its button back and says what happened, whatever the
  answer: an error, something that is not JSON, no answer at all. A network
  that fails left the buttons disabled and "Checking…" on screen (audit
  2026-09-18, D07), and a sign-out the server never saw sent the browser to
  the sign-in page as though it had.
*/

"use strict";

(function () {
  // How long an answer is waited for before it is treated as none.
  const WAIT = 15000;

  // The code of the last refusal send saw, for the one form that answers a
  // refusal by asking for more: the sign-in page, told a code is needed.
  let refusal = "";

  // send returns null when the installation said yes, and otherwise the
  // sentence to show. It never throws.
  async function send(method, path, body) {
    refusal = "";
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), WAIT);
    let response;
    try {
      response = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined,
        credentials: "same-origin",
        signal: abort.signal,
      });
    } catch {
      return "The installation could not be reached. Nothing here can say whether it acted; try again.";
    } finally {
      clearTimeout(timer);
    }
    if (response.ok) return null;
    let message = "The installation did not answer as expected.";
    try {
      const data = await response.json();
      if (data && data.error && typeof data.error.message === "string") message = data.error.message;
      if (data && data.error && typeof data.error.code === "string") refusal = data.error.code;
    } catch {
      // Not JSON; the generic sentence stands.
    }
    return message;
  }

  // ask is send for the answers that carry something back: it returns
  // { data } on yes and { problem } otherwise, and never throws either.
  async function ask(method, path, body) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), WAIT);
    let response;
    try {
      response = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined,
        credentials: "same-origin",
        signal: abort.signal,
      });
    } catch {
      return { problem: "The installation could not be reached. Nothing here can say whether it acted; try again." };
    } finally {
      clearTimeout(timer);
    }
    let data = null;
    try {
      data = await response.json();
    } catch {
      data = null;
    }
    if (response.ok && data) return { data };
    if (response.ok) return { data: {} };
    if (data && data.error && typeof data.error.message === "string") return { problem: data.error.message };
    return { problem: "The installation did not answer as expected." };
  }

  // Copies text, or selects the element showing it where the clipboard is
  // refused, and says which on the button for a moment.
  async function copyText(button, text, shown) {
    const label = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(shown);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = "Selected";
    }
    setTimeout(() => { button.textContent = label; }, 1500);
  }

  // The sign-in page's command, copied as it reads. Where the clipboard is
  // refused the text is selected instead, for the reader to copy.
  // The button is an icon in the box's corner: what happened is said in its
  // label and its title, and drawn as a tick while it is true.
  const copy = document.querySelector(".signin-first [data-copy]");
  if (copy) {
    copy.addEventListener("click", async () => {
      const source = document.getElementById(copy.dataset.copy);
      if (!source) return;
      let said = "Copied";
      try {
        await navigator.clipboard.writeText(source.textContent);
      } catch {
        const range = document.createRange();
        range.selectNodeContents(source);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        said = "Selected; copy it with the keyboard";
      }
      copy.dataset.state = "done";
      copy.title = said;
      copy.setAttribute("aria-label", said);
      setTimeout(() => {
        delete copy.dataset.state;
        copy.title = "Copy";
        copy.setAttribute("aria-label", "Copy the command");
      }, 1500);
    });
  }

  const signinForm = document.getElementById("signin-form");
  if (signinForm) {
    const field = document.getElementById("signin-password");
    const codeRow = document.getElementById("signin-code-row");
    const code = document.getElementById("signin-code");
    const codeLabel = document.getElementById("signin-code-label");
    const recovery = document.getElementById("signin-recovery");
    const button = document.getElementById("signin-submit");
    const status = document.getElementById("signin-status");

    // A recovery code has letters; a phone shows the keyboard that types it.
    recovery.addEventListener("click", () => {
      const toRecovery = code.inputMode === "numeric";
      code.inputMode = toRecovery ? "text" : "numeric";
      codeLabel.textContent = toRecovery ? "Recovery code" : "Code from your authenticator app";
      recovery.textContent = toRecovery ? "Use the code from the app" : "Use a recovery code";
      code.value = "";
      code.focus();
    });

    signinForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      button.disabled = true;
      status.textContent = "Checking…";
      const body = { password: field.value };
      if (!codeRow.hidden && code.value.trim() !== "") body.code = code.value.trim();
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/session", body);
      } finally {
        if (problem === null) {
          window.location.assign("/");
        } else if (refusal === "code_required") {
          // Said before the password was read: it stays, and the code is
          // asked for beside it.
          codeRow.hidden = false;
          status.textContent = problem;
          code.focus();
          button.disabled = false;
        } else {
          status.textContent = problem;
          field.value = "";
          code.value = "";
          field.focus();
          button.disabled = false;
        }
      }
    });
  }

  // Signed out means the server said it ended the session. Until it does,
  // the session may still be good, so the browser stays where it is and the
  // button says it did not work rather than showing the sign-in page, which
  // would look the same as success.
  const signOut = document.getElementById("sign-out");
  if (signOut) {
    signOut.addEventListener("click", async () => {
      signOut.disabled = true;
      signOut.textContent = "Signing out…";
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("DELETE", "/api/v1/session");
      } finally {
        if (problem === null) {
          window.location.assign("/login");
        } else {
          signOut.textContent = "Not signed out. Try again";
          signOut.title = problem;
          signOut.disabled = false;
        }
      }
    });
  }

  const passwordForm = document.getElementById("password-form");
  if (passwordForm) {
    const current = document.getElementById("password-current");
    const next = document.getElementById("password-next");
    const again = document.getElementById("password-again");
    const codeRow = document.getElementById("password-code-row");
    const code = document.getElementById("password-code");
    const button = document.getElementById("password-submit");
    const status = document.getElementById("password-status");
    passwordForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (next.value !== again.value) {
        status.textContent = "The two new passwords are not the same.";
        return;
      }
      button.disabled = true;
      status.textContent = "Saving…";
      const body = { password: current.value, next: next.value };
      if (codeRow && !codeRow.hidden) body.code = code.value.trim();
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/password", body);
      } finally {
        status.textContent = problem === null
          ? "Changed. Every other session has been signed out."
          : problem;
        current.value = "";
        if (code) code.value = "";
        if (problem === null) {
          next.value = "";
          again.value = "";
        }
        button.disabled = false;
      }
    });
  }

  // The second factor, under Security: its state, setting it up
  // from a code to scan, the recovery codes shown once, and the two changes
  // that ask for the password and a code again.
  const factor = document.getElementById("factor");
  if (factor) {
    const state = document.getElementById("factor-state");
    const warning = document.getElementById("factor-warning");
    const offPart = document.getElementById("factor-off");
    const start = document.getElementById("factor-start");
    const setup = document.getElementById("factor-setup");
    const qr = document.getElementById("factor-qr");
    const secret = document.getElementById("factor-secret");
    const secretCopy = document.getElementById("factor-secret-copy");
    const setupCode = document.getElementById("factor-code");
    const setupPassword = document.getElementById("factor-password");
    const confirm = document.getElementById("factor-confirm");
    const cancel = document.getElementById("factor-cancel");
    const codes = document.getElementById("factor-codes");
    const codeList = document.getElementById("factor-code-list");
    const codesCopy = document.getElementById("factor-codes-copy");
    const codesDone = document.getElementById("factor-codes-done");
    const onPart = document.getElementById("factor-on");
    const left = document.getElementById("factor-left");
    const newCodes = document.getElementById("factor-new-codes");
    const turnOff = document.getElementById("factor-turn-off");
    const step = document.getElementById("factor-step");
    const stepPassword = document.getElementById("factor-step-password");
    const stepCode = document.getElementById("factor-step-code");
    const stepSubmit = document.getElementById("factor-step-submit");
    const stepCancel = document.getElementById("factor-step-cancel");
    const status = document.getElementById("factor-status");
    const passwordCode = document.getElementById("password-code-row");
    let stepAction = "";
    let shownCodes = [];

    function show(part) {
      offPart.hidden = part !== "off";
      setup.hidden = part !== "setup";
      codes.hidden = part !== "codes";
      onPart.hidden = part !== "on";
      if (part !== "on") step.hidden = true;
    }

    function setState(on) {
      state.dataset.state = on ? "on" : "off";
      state.textContent = on ? "On" : "Off";
      if (passwordCode) passwordCode.hidden = !on;
    }

    // The modules as one path, with the four-module quiet zone the standard
    // asks for around them.
    function drawCode(rows) {
      const n = rows.length;
      const svg = "http://www.w3.org/2000/svg";
      while (qr.firstChild) qr.removeChild(qr.firstChild);
      qr.setAttribute("viewBox", "0 0 " + (n + 8) + " " + (n + 8));
      const ground = document.createElementNS(svg, "rect");
      ground.setAttribute("class", "factor-qr-ground");
      ground.setAttribute("width", String(n + 8));
      ground.setAttribute("height", String(n + 8));
      qr.appendChild(ground);
      let d = "";
      rows.forEach((row, y) => {
        for (let x = 0; x < row.length; x++) {
          if (row[x] === "1") d += "M" + (x + 4) + " " + (y + 4) + "h1v1h-1z";
        }
      });
      const path = document.createElementNS(svg, "path");
      path.setAttribute("class", "factor-qr-ink");
      path.setAttribute("d", d);
      qr.appendChild(path);
    }

    function showCodes(list) {
      shownCodes = list;
      while (codeList.firstChild) codeList.removeChild(codeList.firstChild);
      for (const c of list) {
        const item = document.createElement("li");
        const text = document.createElement("code");
        text.textContent = c;
        item.appendChild(text);
        codeList.appendChild(item);
      }
      show("codes");
      codesDone.focus();
    }

    async function load() {
      const { data, problem } = await ask("GET", "/api/v1/factor");
      if (problem) {
        state.dataset.state = "unknown";
        state.textContent = "Not known";
        status.textContent = problem;
        return;
      }
      setState(data.on);
      warning.hidden = !(data.on && data.wrong_before > 0);
      if (data.on && data.wrong_before > 0) {
        warning.textContent = data.wrong_before === 1
          ? "A wrong code was sent with the right password before this sign-in. If that was not you, change the password."
          : data.wrong_before + " wrong codes were sent with the right password before this sign-in. If that was not you, change the password.";
      }
      if (data.on) {
        left.textContent = data.recovery_left === 1
          ? "1 recovery code left."
          : data.recovery_left + " recovery codes left.";
        show("on");
      } else {
        show("off");
      }
    }

    start.addEventListener("click", async () => {
      start.disabled = true;
      status.textContent = "Making a code to scan…";
      let answer = { problem: "The installation did not answer as expected." };
      try {
        answer = await ask("POST", "/api/v1/factor/setup");
      } finally {
        start.disabled = false;
        if (answer.problem) {
          status.textContent = answer.problem;
        } else {
          drawCode(answer.data.qr);
          secret.textContent = answer.data.secret;
          status.textContent = "";
          show("setup");
          setupCode.focus();
        }
      }
    });

    secretCopy.addEventListener("click", () => copyText(secretCopy, secret.textContent.replace(/ /g, ""), secret));

    cancel.addEventListener("click", () => {
      setupCode.value = "";
      setupPassword.value = "";
      while (qr.firstChild) qr.removeChild(qr.firstChild);
      secret.textContent = "";
      status.textContent = "";
      show("off");
    });

    setup.addEventListener("submit", async (event) => {
      event.preventDefault();
      confirm.disabled = true;
      status.textContent = "Checking…";
      let answer = { problem: "The installation did not answer as expected." };
      try {
        answer = await ask("POST", "/api/v1/factor/on", { password: setupPassword.value, code: setupCode.value.trim() });
      } finally {
        setupPassword.value = "";
        setupCode.value = "";
        confirm.disabled = false;
        if (answer.problem) {
          status.textContent = answer.problem;
        } else {
          while (qr.firstChild) qr.removeChild(qr.firstChild);
          secret.textContent = "";
          setState(true);
          status.textContent = "On. Every other session has been signed out.";
          showCodes(answer.data.recovery || []);
        }
      }
    });

    codesCopy.addEventListener("click", () => copyText(codesCopy, shownCodes.join("\n"), codeList));

    codesDone.addEventListener("click", () => {
      shownCodes = [];
      while (codeList.firstChild) codeList.removeChild(codeList.firstChild);
      status.textContent = "";
      load();
    });

    function openStep(action) {
      stepAction = action;
      stepSubmit.textContent = action === "off" ? "Turn off" : "Make new codes";
      step.hidden = false;
      status.textContent = action === "off"
        ? "Turning it off asks for the password and a code."
        : "New codes replace every old one, and ask for the password and a code.";
      stepPassword.focus();
    }

    newCodes.addEventListener("click", () => openStep("recovery"));
    turnOff.addEventListener("click", () => openStep("off"));
    stepCancel.addEventListener("click", () => {
      step.hidden = true;
      stepPassword.value = "";
      stepCode.value = "";
      status.textContent = "";
    });

    step.addEventListener("submit", async (event) => {
      event.preventDefault();
      stepSubmit.disabled = true;
      status.textContent = "Checking…";
      const path = stepAction === "off" ? "/api/v1/factor/off" : "/api/v1/factor/recovery";
      let answer = { problem: "The installation did not answer as expected." };
      try {
        answer = await ask("POST", path, { password: stepPassword.value, code: stepCode.value.trim() });
      } finally {
        stepPassword.value = "";
        stepCode.value = "";
        stepSubmit.disabled = false;
        if (answer.problem) {
          status.textContent = answer.problem;
        } else if (stepAction === "off") {
          status.textContent = "Off. Every other session has been signed out.";
          load();
        } else {
          status.textContent = "";
          showCodes(answer.data.recovery || []);
        }
      }
    });

    load();
  }
})();
