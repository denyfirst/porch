/*
  Signing in and out, the first visit's setup, confirming it's you, changing
  the password and the second factor, the Copy beside the setup page's one
  command, and the rail's fold on a phone. Nothing else.

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
    const code = data && data.error && typeof data.error.code === "string" ? data.error.code : "";
    if (data && data.error && typeof data.error.message === "string") return { problem: data.error.message, code };
    return { problem: "The installation did not answer as expected.", code };
  }

  // A change to how the installation is signed into needs a session signed
  // in, or confirmed, in the last ten minutes. Past that the installation
  // says so, and the page that asks again is opened; it comes back here.
  function confirmFirst(code) {
    if (code !== "confirm_required") return false;
    window.location.assign("/confirm");
    return true;
  }

  // Six boxes drawn over the one field a code from the app is typed into.
  // The field is still what is typed into, pasted into and filled by a
  // password manager, and what a screen reader reads; the boxes only show
  // it, a digit each, and where the next one goes. A recovery code has
  // letters and is typed into the same field, drawn as a field.
  function digitBoxes(field) {
    const holder = field && field.parentElement;
    if (!holder || !holder.classList.contains("digits")) return null;
    const boxes = [];
    for (let i = 0; i < 6; i++) {
      const box = document.createElement("span");
      box.className = "digit";
      box.setAttribute("aria-hidden", "true");
      holder.appendChild(box);
      boxes.push(box);
    }
    function draw() {
      if (holder.dataset.mode === "text") return;
      // Some apps show the code as "123 456", and copy it that way.
      const digits = field.value.replace(/\D/g, "").slice(0, 6);
      if (field.value !== digits) field.value = digits;
      const now = document.activeElement === field ? Math.min(digits.length, 5) : -1;
      boxes.forEach((box, i) => {
        box.textContent = digits[i] || "";
        if (i === now) box.dataset.now = "";
        else delete box.dataset.now;
      });
    }
    field.addEventListener("input", draw);
    field.addEventListener("focus", draw);
    field.addEventListener("blur", draw);
    holder.dataset.mode = "digits";
    field.maxLength = 7;
    holder.classList.add("digits-drawn");
    draw();
    return {
      // Switches between the app's digits and a recovery code.
      text(on) {
        holder.dataset.mode = on ? "text" : "digits";
        field.inputMode = on ? "text" : "numeric";
        field.maxLength = on ? 40 : 7;
        field.value = "";
        draw();
      },
      clear() {
        field.value = "";
        draw();
      },
    };
  }

  // A Copy drawn as an icon: what happened is said in its label and its
  // title, and drawn as a tick while it is true. Where the clipboard is
  // refused the text is selected instead, for the reader to copy.
  async function copyIcon(button, text, shown) {
    let said = "Copied";
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const range = document.createRange();
      range.selectNodeContents(shown);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      said = "Selected; copy it with the keyboard";
    }
    const label = button.getAttribute("aria-label");
    button.dataset.state = "done";
    button.title = said;
    button.setAttribute("aria-label", said);
    setTimeout(() => {
      delete button.dataset.state;
      button.title = "Copy";
      button.setAttribute("aria-label", label);
    }, 1500);
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

  // The setup page's command, copied as it reads: an icon in the box.
  const copy = document.querySelector(".signin-first [data-copy]");
  if (copy) {
    copy.addEventListener("click", () => {
      const source = document.getElementById(copy.dataset.copy);
      if (source) copyIcon(copy, source.textContent, source);
    });
  }

  // On a phone the rail folds into a bar with a button that opens it. The
  // fold is added here, so a page whose script did not run draws the rail
  // open rather than shut.
  const rail = document.querySelector(".rail");
  const railMenu = document.getElementById("rail-menu");
  if (rail && railMenu) {
    rail.classList.add("rail-folds");
    const fold = (open) => {
      railMenu.setAttribute("aria-expanded", String(open));
      railMenu.setAttribute("aria-label", open ? "Close the menu" : "Menu");
      rail.classList.toggle("rail-open", open);
    };
    railMenu.addEventListener("click", () => fold(railMenu.getAttribute("aria-expanded") !== "true"));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && rail.classList.contains("rail-open")) {
        fold(false);
        railMenu.focus();
      }
    });
  }

  const signinForm = document.getElementById("signin-form");
  if (signinForm) {
    const field = document.getElementById("signin-password");
    const passwordStep = document.getElementById("signin-password-step");
    const codeRow = document.getElementById("signin-code-row");
    const back = document.getElementById("signin-back");
    const code = document.getElementById("signin-code");
    const codeLabel = document.getElementById("signin-code-label");
    const codeSub = document.getElementById("signin-code-sub");
    const recovery = document.getElementById("signin-recovery");
    const button = document.getElementById("signin-submit");
    const status = document.getElementById("signin-status");
    const boxes = digitBoxes(code);

    // The two steps of one card: the password, then the code. The password
    // step is hidden, not emptied, while the code is asked for.
    function step(toCode) {
      passwordStep.hidden = toCode;
      codeRow.hidden = !toCode;
      button.textContent = toCode ? "Verify" : "Sign in";
      if (!toCode) {
        if (boxes) boxes.clear();
        else code.value = "";
      }
    }

    back.addEventListener("click", () => {
      step(false);
      status.textContent = "";
      field.focus();
    });

    // A recovery code has letters; a phone shows the keyboard that types it.
    recovery.addEventListener("click", () => {
      const toRecovery = code.inputMode === "numeric";
      if (boxes) boxes.text(toRecovery);
      else code.inputMode = toRecovery ? "text" : "numeric";
      codeLabel.textContent = toRecovery ? "Recovery code" : "Code from your authenticator app";
      codeSub.textContent = toRecovery
        ? "Enter one of the recovery codes you kept. Each works once."
        : "Enter the 6-digit code from your authenticator app.";
      recovery.textContent = toRecovery ? "Use the code from the app instead" : "Use a recovery code instead";
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
          // Said before the password was read: it stays, out of sight, and
          // the code is asked for in the second step.
          step(true);
          status.textContent = "";
          code.focus();
          button.disabled = false;
        } else {
          // Wrong, whichever of the two was: both are asked for again, from
          // the first step, and nothing says which was right.
          step(false);
          status.textContent = problem;
          field.value = "";
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
    // The words are a label beside a mark, which a narrowed rail shows alone.
    const signOutLabel = signOut.querySelector(".rail-label") || signOut;
    signOut.addEventListener("click", async () => {
      signOut.disabled = true;
      signOutLabel.textContent = "Signing out…";
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("DELETE", "/api/v1/session");
      } finally {
        if (problem === null) {
          window.location.assign("/login");
        } else {
          signOutLabel.textContent = "Not signed out. Try again";
          signOut.title = problem;
          signOut.disabled = false;
        }
      }
    });
  }

  // The password, under Security. The current one is asked for whatever
  // else is true, and a session older than ten minutes is sent to confirm
  // it's you first.
  const passwordForm = document.getElementById("password-form");
  if (passwordForm) {
    const current = document.getElementById("password-current");
    const next = document.getElementById("password-next");
    const again = document.getElementById("password-again");
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
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/password", { password: current.value, next: next.value });
      } finally {
        if (problem !== null && confirmFirst(refusal)) {
          status.textContent = "Confirm it's you first…";
        } else {
          status.textContent = problem === null
            ? "Changed. Every other session has been signed out."
            : problem;
        }
        current.value = "";
        if (problem === null) {
          next.value = "";
          again.value = "";
        }
        button.disabled = false;
      }
    });
  }

  // The second factor, under Security: its state, setting it up from a code
  // to scan, the recovery codes shown once, new codes and turning it off.
  // Each change is sent as it is; one the installation says needs a fresh
  // confirmation opens the page that asks for it.
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
    const status = document.getElementById("factor-status");
    const boxes = digitBoxes(setupCode);
    let shownCodes = [];

    function show(part) {
      offPart.hidden = part !== "off";
      setup.hidden = part !== "setup";
      codes.hidden = part !== "codes";
      onPart.hidden = part !== "on";
    }

    function setState(on) {
      state.dataset.state = on ? "on" : "off";
      state.textContent = on ? "On" : "Off";
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

    function forgetSetup() {
      if (boxes) boxes.clear();
      else setupCode.value = "";
      while (qr.firstChild) qr.removeChild(qr.firstChild);
      secret.textContent = "";
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
          ? "A wrong code was sent with the right password before this sign-in. If that was not you, the password has leaked: change it below."
          : data.wrong_before + " wrong codes were sent with the right password before this sign-in. If that was not you, the password has leaked: change it below.";
      }
      if (data.on) {
        left.textContent = (data.recovery_left === 1 ? "1 of 10 unused." : data.recovery_left + " of 10 unused.") +
          " Each one signs in once, in place of a code.";
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
          status.textContent = confirmFirst(answer.code) ? "Confirm it's you first…" : answer.problem;
        } else {
          drawCode(answer.data.qr);
          secret.textContent = answer.data.secret;
          status.textContent = "";
          show("setup");
          setupCode.focus();
        }
      }
    });

    secretCopy.addEventListener("click", () => copyIcon(secretCopy, secret.textContent.replace(/ /g, ""), secret));

    cancel.addEventListener("click", () => {
      forgetSetup();
      status.textContent = "";
      show("off");
    });

    setup.addEventListener("submit", async (event) => {
      event.preventDefault();
      confirm.disabled = true;
      status.textContent = "Checking…";
      let answer = { problem: "The installation did not answer as expected." };
      try {
        answer = await ask("POST", "/api/v1/factor/on", { code: setupCode.value.trim() });
      } finally {
        confirm.disabled = false;
        if (answer.problem) {
          if (boxes) boxes.clear();
          else setupCode.value = "";
          status.textContent = confirmFirst(answer.code) ? "Confirm it's you first…" : answer.problem;
        } else {
          forgetSetup();
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

    // New codes and turning off are asked about first, on the page: each
    // undoes something that cannot be had back.
    async function change(action, button) {
      const question = action === "off"
        ? "Turn off two-step sign-in? Signing in will ask for the password alone, and every other session is signed out."
        : "Make new recovery codes? Every code made before stops working.";
      if (!window.confirm(question)) return;
      button.disabled = true;
      status.textContent = "Checking…";
      const path = action === "off" ? "/api/v1/factor/off" : "/api/v1/factor/recovery";
      let answer = { problem: "The installation did not answer as expected." };
      try {
        answer = await ask("POST", path);
      } finally {
        button.disabled = false;
        if (answer.problem) {
          status.textContent = confirmFirst(answer.code) ? "Confirm it's you first…" : answer.problem;
        } else if (action === "off") {
          status.textContent = "Off. Every other session has been signed out.";
          load();
        } else {
          status.textContent = "";
          showCodes(answer.data.recovery || []);
        }
      }
    }

    newCodes.addEventListener("click", () => change("recovery", newCodes));
    turnOff.addEventListener("click", () => change("off", turnOff));

    load();
  }

  // The first visit: the setup code from the log and the password chosen
  // with it. Once set, the installation has signed in, and Security is
  // where two-step sign-in is turned on.
  const setupForm = document.getElementById("setup-form");
  if (setupForm) {
    const code = document.getElementById("setup-code");
    const password = document.getElementById("setup-password");
    const again = document.getElementById("setup-again");
    const button = document.getElementById("setup-submit");
    const status = document.getElementById("setup-status");
    setupForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (password.value !== again.value) {
        status.textContent = "The two passwords are not the same.";
        again.focus();
        return;
      }
      button.disabled = true;
      status.textContent = "Saving…";
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/setup", { code: code.value.trim(), password: password.value });
      } finally {
        if (problem === null) {
          window.location.assign("/security");
        } else if (refusal === "already_set_up") {
          window.location.assign("/login");
        } else {
          status.textContent = problem;
          if (refusal === "weak_password") {
            password.value = "";
            again.value = "";
            password.focus();
          } else {
            code.value = "";
            code.focus();
          }
          button.disabled = false;
        }
      }
    });
  }

  // Confirm it's you: a code from the app, or a recovery code, where the
  // second factor is on, and the password where it is not. Five wrong
  // answers end the session, and the installation says so.
  const confirmForm = document.getElementById("confirm-form");
  if (confirmForm) {
    const codeRow = document.getElementById("confirm-code-row");
    const code = document.getElementById("confirm-code");
    const codeLabel = document.getElementById("confirm-code-label");
    const recovery = document.getElementById("confirm-recovery");
    const passwordRow = document.getElementById("confirm-password-row");
    const password = document.getElementById("confirm-password");
    const button = document.getElementById("confirm-submit");
    const status = document.getElementById("confirm-status");
    const boxes = digitBoxes(code);
    let withCode = false;

    recovery.addEventListener("click", () => {
      const toRecovery = code.inputMode === "numeric";
      if (boxes) boxes.text(toRecovery);
      else code.inputMode = toRecovery ? "text" : "numeric";
      codeLabel.textContent = toRecovery ? "Recovery code" : "Code from your authenticator app";
      recovery.textContent = toRecovery ? "Use the code from the app instead" : "Use a recovery code instead";
      code.value = "";
      code.focus();
    });

    (async () => {
      const { data, problem } = await ask("GET", "/api/v1/factor");
      if (problem) {
        status.textContent = problem;
        return;
      }
      withCode = Boolean(data.on);
      codeRow.hidden = !withCode;
      passwordRow.hidden = withCode;
      code.required = withCode;
      password.required = !withCode;
      status.textContent = "";
      button.disabled = false;
      (withCode ? code : password).focus();
    })();

    confirmForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      button.disabled = true;
      status.textContent = "Checking…";
      const body = withCode ? { code: code.value.trim() } : { password: password.value };
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/session/confirm", body);
      } finally {
        if (problem === null) {
          window.location.assign("/security");
        } else if (refusal === "signed_out" || refusal === "sign_in") {
          window.location.assign("/login");
        } else {
          status.textContent = problem;
          password.value = "";
          if (boxes) boxes.clear();
          else code.value = "";
          (withCode ? code : password).focus();
          button.disabled = false;
        }
      }
    });
  }
})();
