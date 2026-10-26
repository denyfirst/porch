/*
  denyfirst
  ---------
  Every node on this page is built with createElement and textContent.
  innerHTML, insertAdjacentHTML, document.write and outerHTML appear nowhere,
  and a test in internal/web asserts that they never will.

  The reason is specific rather than general. A successful scan returns the
  target the caller sent, by design, and hostnames are attacker-chosen. The
  moment that value reaches a markup parser it stops being data. Building
  nodes directly means there is no parser to reach: a string assigned to
  textContent is a string, whatever it contains.
*/

"use strict";

const form = document.getElementById("scan-form");
const input = document.getElementById("target");
const button = document.getElementById("submit");
const result = document.getElementById("result");

const VERDICT_ORDER = { insecure: 3, weak: 2, strong: 1 };

/*
  One script, three checks.

  The pages differ in four things: which endpoint they call, which method page
  their standing limits point at, what the button says while it waits, and how
  a report is drawn. Everything else — the builders, the verdict handling, the
  findings, the notes, the download, the failure path, the counter — is the
  same work and is written once. Two scripts would be two copies of all of it,
  and the copy nobody is looking at is the one that falls behind.

  Which check a page is comes from the page rather than from the path, because
  a path is a thing that moves. The form carries it in a data attribute, which
  the markup can set and the CSP cannot object to; there is no inline script
  anywhere on this site and this does not add one.
*/
// How each check works, and its limits: docs/checks.md on GitHub.
const CHECKS_DOC = "https://github.com/denyfirst/porch/blob/main/docs/checks.md";

const CHECKS = {
  tls: {
    label: "Transport",
    says: "TLS versions, ciphers and the certificate",
    endpoint: "/api/v1/tls/scan",
    methodPage: CHECKS_DOC + "#tls",
    working: "Opening handshakes at every TLS version. This takes a few seconds.",
    build: (data) => buildTLS(data),
  },
  web: {
    label: "Reach",
    says: "HTTPS redirects, HSTS, cookies and headers",
    endpoint: "/api/v1/web/scan",
    methodPage: CHECKS_DOC + "#web",
    working: "Reading how the site answers, over HTTPS and over plaintext.",
    build: (data) => buildWeb(data),
  },
  dns: {
    label: "DNS",
    says: "name servers, DNSSEC and zone transfers",

    endpoint: "/api/v1/dns/scan",
    methodPage: CHECKS_DOC + "#dns",
    working: "Reading the delegation, the records at the name and the DNSSEC chain.",
    build: (data) => buildDNS(data),
  },
  // Not in CHECK_ORDER: the console runs every check it is given against one
  // name, and this is not a check.
  //
  // It is on the console's list all the same — hiding it meant somebody had to
  // know the page existed to find it, which is the worst way to offer the one
  // mode that answers "what have I got" — but as a link to its own page rather
  // than as a box. The page has a field for an address range and this form has
  // none, so a box here ran two thirds of the mode and reported the reverse
  // walk as never asked, every time, with nothing on the page to do about it.
  //
  // The entry stays in CHECKS because the page itself runs from it: the label,
  // the endpoint, the working line and the builder are all read there.
  names: {
    label: "Names",
    says: "names under the domain, from certificates and DNS",

    endpoint: "/api/v1/names/scan",
    methodPage: CHECKS_DOC + "#names",
    working: "Asking what has been published under this domain, and what each name is doing now.",
    build: (data) => buildNames(data),
  },
  mail: {
    label: "Mail",
    says: "SPF, DKIM, DMARC, MTA-STS and the mail servers",

    endpoint: "/api/v1/mail/scan",
    methodPage: CHECKS_DOC + "#mail",
    working: "Reading the sender policy, the DMARC record, the mail exchangers and what protects them.",
    build: (data) => buildMail(data),
  },
};

// The order the console runs and draws them in.
//
// Fixed rather than taken from the object, because a report whose sections
// move between two scans of an unchanged estate is a diff a reader has to work
// out is not a change.
const CHECK_ORDER = ["tls", "web", "mail", "dns"];

// The demonstration says so on its body. A few things an installation offers
// its operator mean nothing there: a download of a report about our own
// domain, and a count of our own checks.
const DEMO_SITE = document.body.dataset.site === "demo";

// Defaulting to the TLS check rather than to nothing, because a page that
// declared no check would otherwise fail at the first click with an error
// about undefined rather than about anything a reader could act on.
const CHECK_NAME = CHECKS[(form && form.dataset.check) || "tls"] ? ((form && form.dataset.check) || "tls") : "tls";
const CHECK = CHECKS[CHECK_NAME];

// rangesAsked reads the address ranges typed beside the domain, where this
// installation offers the field at all.
//
// Sent only when something was typed: an empty list would be a caller asking
// for a walk of nothing, and the service would have to decide what that meant.
function rangesAsked() {
  const field = document.getElementById("ranges");
  if (!field) return null;

  const ranges = field.value.split(",").map(r => r.trim()).filter(Boolean);
  return ranges.length ? { ranges: ranges } : null;
}

// MAX_KNOWN is how many names a list may carry, and it is the service's bound
// said again here so the page can refuse before the request rather than after.
//
// internal/knownnames.MaxNames is the one that decides. This is the same
// number for the sake of the message: a list refused by the service is refused
// with a sentence in place of a report, and a list refused here is refused
// beside the field somebody typed it into.
const MAX_KNOWN = 1000;

// knownAsked reads the names somebody already has, typed or loaded from a file.
//
// Split on lines and commas both, because a list arrives as either: a column
// exported out of an inventory, or a row somebody pasted. Comments and the
// notes after a name are dropped the same way the command line drops them, so
// a file that is kept for people stays usable here.
//
// Sent only when something was typed. An empty list would be a caller asking
// for nothing, and the service would have to decide what that meant.
//
// And sent whole. It was cut to MAX_KNOWN here, without a word, so a list
// pasted past the bound lost its tail on the way out and the service — which
// refuses such a list rather than cutting it — never saw enough to refuse. The
// report then listed a thousand names as if they were all of them. A file
// loaded past the bound is still cut where it is loaded, and says so beside
// the field; what somebody typed is theirs to be refused over.
function knownAsked() {
  const field = document.getElementById("known");
  if (!field) return null;

  const names = splitNames(field.value);
  return names.length ? { names: names } : null;
}

// asked is everything the page adds to the domain, in one object.
//
// One function rather than two spread through the caller, because the two grew
// apart once: the console sent ranges and the inventory page sent ranges, and
// a third field would have been added to whichever of them somebody was
// looking at.
function asked() {
  return Object.assign({}, rangesAsked(), knownAsked());
}

// selectorsAsked reads the DKIM selectors typed beside the checks.
//
// The one input a check needs and cannot discover: DNS does not list what is
// beneath a name, so a signing key is found only where somebody says to look.
//
// Sent only to the check that uses them. Every other endpoint refuses a list
// of selectors rather than dropping it, and sending one to the TLS check would
// turn a filled-in field into a failed scan.
function selectorsAsked(name) {
  const field = document.getElementById("selectors");
  if (!field || name !== "mail") return null;

  // Commas or spaces, because somebody pasting "s1 google" means two names and
  // the service refuses a selector that is not a DNS name.
  const named = field.value.split(/[\s,]+/).filter(Boolean);
  return named.length ? { selectors: named } : null;
}

// A .txt of names is read in this browser and put in the box.
//
// Read here rather than uploaded, and that is the whole design of it. There is
// no endpoint that takes a file, nothing is written to disk anywhere, and what
// leaves the page is the names themselves in the same request as the domain —
// the identical thing that happens when somebody types them. A file upload
// would have been a second way in, with a second set of bounds, for a result
// this already gives.
//
// The box is filled rather than the request being built from the file, so that
// somebody can see what was loaded and take a line out before running it.
const knownFile = document.getElementById("known-file");
if (knownFile) {
  // A megabyte, which is the bound the command line puts on the same file. A
  // list of a thousand names is some tens of kilobytes, so anything near this
  // is not an estate.
  const MAX_FILE = 1 << 20;

  knownFile.addEventListener("change", () => {
    const note = document.getElementById("known-file-note");
    const box = document.getElementById("known");
    const file = knownFile.files && knownFile.files[0];
    if (!file || !box) return;

    const say = (text) => { if (note) note.textContent = text; };

    if (file.size > MAX_FILE) {
      say("That file is larger than a list of names: up to a megabyte is read.");
      knownFile.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => say("That file could not be read.");
    reader.onload = () => {
      const names = splitNames(reader.result);
      if (!names.length) {
        say("No names were found in that file.");
        return;
      }

      const already = splitNames(box.value);
      const all = already.concat(names);
      const kept = all.slice(0, MAX_KNOWN);
      box.value = kept.join("\n");

      say(all.length > kept.length
        ? kept.length + " names loaded; the rest were left out, because a list is up to " +
          MAX_KNOWN + " names"
        : names.length + (names.length === 1 ? " name loaded" : " names loaded"));

      // Cleared so that choosing the same file again fires this at all, and
      // so the file's own name is not left sitting under the field.
      knownFile.value = "";
    };
    reader.readAsText(file);
  });
}

// splitNames turns whatever is in the box into a list of names.
function splitNames(text) {
  const out = [];
  for (const line of String(text || "").split(/[\r\n]+/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    for (const part of trimmed.split(/[,\s]+/)) {
      const name = part.trim();
      // Anything after the first name on a line is a note, not a name. A
      // comma-separated row is a row, though, so the split above keeps both
      // shapes and this only stops at whitespace that follows a comma-free
      // name.
      if (name) out.push(name);
      if (!trimmed.includes(",")) break;
    }
  }
  return out;
}

// ── Small builders ──────────────────────────────────────────────────────

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function link(href, text) {
  const a = document.createElement("a");
  // Only http and https are ever rendered. Anything else — javascript:, data:
  // — is shown as plain text instead, so a hostile source list in a response
  // cannot become a clickable script.
  const safe = typeof href === "string" && /^https?:\/\//i.test(href);
  if (!safe) return el("span", null, text);

  a.href = href;
  a.textContent = text;
  a.rel = "noopener noreferrer";
  a.target = "_blank";
  return a;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/*
  Every class name on this page comes from this list and nowhere else.

  Nothing a caller sends reaches a class attribute today: a verdict is written
  by internal/policy, and the API returns one of four fixed strings. So this is
  not closing a hole that is open. It closes the one that opens the first time
  somebody builds a class out of a field that is attacker-chosen, which is one
  line and no warning — a class name is not a script, but it decides what the
  page looks like, and a page that will paste any string into a class attribute
  has handed its appearance to whoever answers.

  It was already done in one place and not in two others, and the difference
  was invisible from either.
*/
const VERDICTS = ["strong", "weak", "insecure"];

function verdictClass(prefix, verdict) {
  return prefix + "-" + (VERDICTS.includes(verdict) ? verdict : "ungraded");
}

// The table cells use their own prefix and fall back to a neutral colour
// rather than to an "ungraded" one, because a blank cell is not a verdict.
function markClass(verdict) {
  return VERDICTS.includes(verdict) ? "mark-" + verdict : "mark-faint";
}

// ── Sections ────────────────────────────────────────────────────────────

function sectionTitle(text) {
  return el("h2", "section-title", text);
}

// The verdict as the page should treat it. The field is omitted from the
// response when nothing could be graded, and an absent value is not the same
// as an unknown one: it means the scan reached nothing.
function verdictOf(data) {
  return data && data.verdict ? data.verdict : "ungraded";
}

// Saving a report, entirely in the browser.
//
// Nothing is asked of the service again and nothing is kept anywhere: the JSON
// already arrived, and this hands the reader the bytes they already have. A
// server endpoint returning the same thing would have to keep the result or
// scan a second time, and this project does neither.
//
// JSON and nothing else, which is a security decision rather than a
// preference. Every string in a report — subjects, names, issuers — is chosen
// by the server that was scanned, and each of the other formats hands those
// strings to something that executes them. A spreadsheet reads a value
// beginning with =, +, - or @ as a formula. A terminal reads an escape
// sequence in a name as an instruction and rewrites what is already on the
// screen, which is a defect this project found in its own command line output.
// A browser reads HTML as markup. JSON escapes a control byte as \u001b and
// carries no executable meaning anywhere, so the format itself is the
// protection rather than something bolted onto it.

// Not the clipboard, and that is a decision rather than an omission.
//
// A clipboard button reads as the same offer and is not. The system clipboard
// is shared with every process on the machine, Windows keeps a history of it
// that any of them can read, and a cloud clipboard sends it off the machine
// entirely. A file goes to one place the reader chose and no further.
//
// What is sensitive in a report is not its contents — everything in it is
// public and was sent by the server to anyone who connected. It is that
// somebody asked about that host. This service undertakes to keep no record
// of what was scanned, by whom or when, and handing that fact to a channel
// every application can read would undo the promise on the reader's side of
// it. Offering both would not be a convenience; it would be the weaker of the
// two, offered without saying so.

// The object URL for the report on screen, and only ever one.
//
// An object URL keeps its blob alive for as long as the document does, so the
// previous one is released before the next is made: a reader who scans twenty
// hosts holds one report in memory rather than twenty.
let reportURL = null;

function downloadLink(data) {
  if (reportURL) {
    URL.revokeObjectURL(reportURL);
    reportURL = null;
  }

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  reportURL = URL.createObjectURL(blob);

  // A link rather than a button driving a synthetic click: it can be
  // right-clicked, opened in a new tab, and read by anything that reads links.
  const anchor = el("a", "download", "Download as JSON");
  anchor.href = reportURL;
  anchor.download = reportFilename(data);
  return anchor;
}

// printButton opens the browser's own print dialogue, which is where a PDF
// comes from.
//
// No PDF is written here. Writing one would mean a library — this project has
// no dependencies — or writing a PDF writer, which can only use the fonts a
// reader already has and so would produce a document that is not this report:
// different type, different rules, different colours. The browser prints what
// is on the screen, with the stylesheet below deciding what a sheet of paper
// gets, so the document somebody hands to an auditor is the report they read.
//
// A button rather than a link, because it does something to this page rather
// than going somewhere.
function printButton() {
  const button = el("button", "download", "Save as PDF");
  button.type = "button";
  button.addEventListener("click", () => window.print());
  return button;
}

// What a report folds: the checked lists and the note sections, which are
// the only details elements a report makes.
const PRINTED_OPEN = "details.checked-list, details.notes-section";

// A sheet of paper says when it was printed. A report handed to an auditor is
// read days later, and a fresh report on an installation carries no time of
// its own. Written as the print dialogue opens, from this machine's clock, into
// the mark only paper shows; nothing leaves the page.
window.addEventListener("beforeprint", () => {
  const stamp = document.getElementById("print-date");
  if (stamp) stamp.textContent = "Printed " + new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";
  // Everything a report folds is printed open, and folded again afterwards
  // only if the reader had not opened it themselves. Paper has no summary to
  // press: a PDF of cyberlek.net on 2026-10-23 carried the DNS card's
  // "6 measured, not graded" and none of the six, among them that the
  // registration ran out in twelve days.
  for (const box of document.querySelectorAll(PRINTED_OPEN)) {
    if (box.open) continue;
    box.open = true;
    box.dataset.printOpened = "1";
  }
});

window.addEventListener("afterprint", () => {
  for (const box of document.querySelectorAll(PRINTED_OPEN)) {
    if (!box.dataset.printOpened) continue;
    box.open = false;
    delete box.dataset.printOpened;
  }
});

// reportFilename builds a name from the target.
//
// The target reaching here is already canonical — the service accepts letters,
// digits, dot, hyphen, underscore and colon in a hostname and nothing else —
// so this is a second fence rather than the first. A colon is legal in an IPv6
// target and illegal in a Windows filename; anything outside the set becomes a
// hyphen; and the whole is cut short, because a name that can be made long is
// a name that ends up somewhere it does not fit.
function reportFilename(data) {
  // The TLS report names a host and port; the web report names a bare host.
  // One filename builder, because a reader saving one of each should get two
  // files named the same way.
  const target = String((data && (data.target || data.host)) || "report").toLowerCase();
  const safe = target
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 60);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  return "denyfirst-" + (safe || "report") + "-" + stamp + "Z.json";
}

function summary(data) {
  const wrap = el("div", "summary");

  // The verdict and the thing it is a verdict on, on one line.
  //
  // Until 2026-09-01 the two sentences below were in this row too, inside the
  // left column. A dl is a block, so the column took the whole width and the
  // stamp — the first thing anybody looks for — wrapped to a line of its own
  // underneath four lines of coverage, below the sentence that explains it.
  // A verdict that arrives after its explanation is a verdict read twice.
  const head = el("div", "summary-head");

  const left = el("div");
  left.appendChild(el("p", "summary-target", data.target || data.host || data.domain || "—"));

  const address = data.tls && data.tls.address;
  const meta = [];
  if (address) meta.push(address);
  if (data.policy) meta.push("graded by " + data.policy);
  // A kept copy says how old it is. The demonstration runs each check at most
  // once every fifteen minutes and hands the report to everybody who asks in
  // that time, and
  // a copy without its age would read as a measurement of now.
  if (data.producedAt && !data.producedAt.startsWith("0001-01-01")) {
    meta.push("measured " + producedAt(data.producedAt));
  }
  if (meta.length) left.appendChild(el("p", "summary-meta", meta.join("  ·  ")));
  // Not on the demonstration: a report there is about our own domain, and a
  // visitor has no use for a copy of it. A copy of your own is where a
  // download matters, because nothing is kept for you.
  if (!DEMO_SITE) {
    const actions = el("p", "summary-actions");
    actions.appendChild(downloadLink(data));
    actions.appendChild(printButton());
    left.appendChild(actions);
  }

  head.appendChild(left);

  const verdict = verdictOf(data);
  const stamp = el("div", "stamp " + verdictClass("stamp", verdict), verdict);
  if (!data.verdict) stamp.textContent = "not graded";
  head.appendChild(stamp);

  wrap.appendChild(head);

  // What a weak or insecure verdict means, under the verdict.
  //
  // The report's likeliest misreading: a red stamp sits next to a trusted
  // chain, a verified staple, transparency, CAA and an accepted post-quantum
  // group, and nothing on the page says why one option outweighs all of that.
  // The sentence is built in internal/policy so that both faces say it in the
  // same words. R16.
  if (verdict === "weak" || verdict === "insecure") {
    wrap.appendChild(el("p", "summary-worst", WORST_CASE));
  }

  // How much of the picture this scan reached, which is what the verdict
  // rests on and what no table says.
  //
  // Labelled, in the same grammar as the certificate rows and the cipher
  // facts. Unlabelled it arrived directly beneath the worst-case sentence and
  // the two read as one paragraph — and an unlabelled sentence under a table
  // is exactly what made the key exchange invisible until somebody looked
  // twice.
  if (data.coverage) {
    const reached = el("dl", "pairs summary-pairs");
    reached.appendChild(el("dt", null, "Coverage"));
    reached.appendChild(el("dd", "summary-coverage", data.coverage));
    wrap.appendChild(reached);
  }

  return wrap;
}

/*
  What happened at this version, in the words the probe used.

  This cell said "accepted" or "refused" and nothing else, and the second word
  was wrong more often than it was right. Only one kind of failure is a
  refusal: the server answered and declined. Our own client not offering the
  version, a name that did not resolve, a timeout, a reset, a connection the
  service would not make — all of them leave `supported` false as well, and
  all of them were printed as "refused".

  The direction of that error is what makes it worth a fix rather than a note.
  A row reading "TLS 1.0  refused" is a row in the server's favour: refusing an
  obsolete version is the correct configuration, and the page was crediting
  servers with it on the strength of a handshake that never happened. The
  server may well still accept TLS 1.0.

  The API carries both halves — `refused` says which kind, `error` says what
  happened — and neither was read here.
*/
function outcomeCell(v) {
  const cell = el("td", v.supported ? null : "mark-faint");
  cell.appendChild(el("span", null,
    v.supported ? "accepted" : (v.refused ? "refused" : "not measured")));
  // The reason only where it says something the word does not. Beside
  // "refused" it repeated it — "refused  server refused TLS 1.0" — and the
  // SSL 3.0 row, which carries no such sentence, read differently from the
  // rows above it.
  if (!v.supported && !v.refused && v.error) cell.appendChild(el("p", "row-note", v.error));
  return cell;
}

function versions(tls) {
  if (!tls || !Array.isArray(tls.versions)) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Protocol versions"));

  const table = el("table", "rows");
  const head = el("tr");
  // "Outcome" rather than "Offered". The column has never held an answer to
  // "was it offered" — it holds what happened, and one of the three things it
  // can now say is that nothing did.
  for (const label of ["Version", "Outcome", "Grade"]) {
    head.appendChild(el("th", null, label));
  }
  table.appendChild(el("thead")).appendChild(head);

  const body = el("tbody");
  for (const v of tls.versions) {
    const row = el("tr");
    row.appendChild(el("td", null, v.name));
    row.appendChild(outcomeCell(v));

    const grade = v.supported && v.grade ? v.grade.verdict : "";
    const cell = el("td", markClass(grade),
      grade ? (v.grade.preferred ? grade + "  ·  preferred" : grade) : "—");
    row.appendChild(cell);

    body.appendChild(row);
  }

  // SSL 3.0, asked with a hand-written hello because Go's client cannot speak
  // it. Beside the other versions and in the same three words, so a reader
  // scanning the list for the obsolete one finds it where they look — and
  // "refused" only where the server said no (R4).
  const ssl3 = tls.legacy && tls.legacy.asked ? tls.legacy.ssl3 : null;
  if (ssl3) {
    const row = el("tr");
    row.appendChild(el("td", null, "SSL 3.0"));
    row.appendChild(outcomeCell({ supported: ssl3.accepted, refused: ssl3.refused, error: ssl3.reason }));
    // The suite it was accepted with goes here too, since this is now the
    // only row SSL 3.0 has.
    const grade = ssl3.accepted && ssl3.versionGrade ? ssl3.versionGrade.verdict : "";
    const suite = ssl3.accepted && ssl3.suite ? "  ·  " + ssl3.suite.name : "";
    row.appendChild(el("td", markClass(grade), grade ? grade + suite : "—"));
    body.appendChild(row);
  }

  table.appendChild(body);
  frag.appendChild(table);

  return frag;
}

// What the hand-written hellos were answered with.
//
// The same rows the terminal prints, in the same order and words (R16). Titled
// as asked by hand, because these are not an enumeration: each is one hello
// offering every suite of a family at once, and "export: refused" means none of
// them was accepted by that hello, not that each was tried.
// What each of the name's addresses answered when asked on its own.
//
// The same rows and the same words as printAddresses in the command line (R16).
// Whether they agree is said once, in the notes.
function addresses(tls) {
  const list = tls && tls.addresses;
  if (!list || !list.length) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Each address, asked on its own"));

  const table = el("table", "rows");
  const body = el("tbody");
  for (const a of list) {
    const row = el("tr");
    row.appendChild(el("td", null, a.address));
    row.appendChild(el("td", a.answered ? null : "mark-faint", addressSays(a)));
    body.appendChild(row);
  }
  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

function addressSays(a) {
  if (!a.answered) return "no answer: " + a.reason;
  const cert = a.certificate ? a.certificate.slice(0, 16) + "…" : "none presented";
  return a.version + " " + a.suite + ", certificate " + cert;
}

function legacy(tls) {
  const l = tls && tls.legacy;
  if (!l || !l.asked) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  // What this section is, said under its title. It read as a second list of
  // versions with SSL 3.0 in it twice; it is the suite families the ordinary
  // enumeration cannot offer, each asked for in one hello of its own. SSL 3.0
  // is a version and stays in the version table.
  //
  // Why they are asked this way is the method page's to say, not the
  // report's: the note says how to read a row, and the link says the rest.
  frag.appendChild(sectionTitle("Obsolete suites, asked for directly"));
  const note = el("p", "section-note",
    "Each family was offered on its own, every suite in it at once. " +
    "Refused means the server accepted none of them. ");
  const why = el("a", "notes-method-link", "Why these are asked separately");
  why.href = CHECKS_DOC + "#obsolete-suites";
  note.appendChild(why);
  frag.appendChild(note);

  const table = el("table", "rows");
  const body = el("tbody");

  const answer = (label, a) => {
    const row = el("tr");
    row.appendChild(el("td", null, label));
    row.appendChild(outcomeCell({ supported: a.accepted, refused: a.refused, error: a.reason }));
    const suite = a.accepted && a.suite ? a.suite : null;
    row.appendChild(el("td", markClass(suite ? suite.verdict : ""),
      suite ? suite.verdict + "  ·  " + suite.name + " at " + a.version : "—"));
    body.appendChild(row);
  };
  // The same rows the terminal prints, in its words (R16). Named for what
  // each family is, because "export" and "NULL" alone meant nothing to a
  // reader who had not met them. Older reports carry neither ffdhe nor
  // anonymous, so each is drawn only where it was sent.
  answer("Export-grade", l.export);
  answer("NULL, no encryption", l.null);
  if (l.ffdhe) answer("Finite-field DHE", l.ffdhe);
  if (l.anonymous) answer("Anonymous, no certificate", l.anonymous);

  const f = l.fallback;
  const row = el("tr");
  row.appendChild(el("td", null, "Downgrade signal"));
  row.appendChild(el("td", f.measured ? null : "mark-faint",
    f.measured ? (f.honoured ? "honoured" : "not honoured") : "not measured"));
  row.appendChild(el("td", null, f.measured
    ? "a hello claiming only " + f.asked + (f.honoured ? " was refused" : " was answered")
    : f.reason));
  body.appendChild(row);

  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

function ciphers(tls, report) {
  if (!tls || !Array.isArray(tls.versions)) return document.createDocumentFragment();

  const offered = tls.versions.filter(v => v.supported && Array.isArray(v.ciphers) && v.ciphers.length);
  if (!offered.length) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Cipher suites accepted"));

  for (const v of offered) {
    frag.appendChild(el("p", "group-label", v.name));

    // Beside the list rather than only in the folded notes at the foot.
    //
    // "Cipher suites accepted" over a list that stopped early reads as the
    // whole set, and the suites missing from it are the weak ones —
    // enumeration finds them strongest first. The note that says so is
    // counted in the summary line but the block is shut under every verdict
    // except ungraded, so under a weak or insecure verdict the reader is
    // looking at a truncated table with nothing on it to say so.
    //
    // Negated rather than compared to false: an absent field is treated as an
    // incomplete list, so a response that forgets to say gets the cautious
    // reading. That is the same polarity the Go field was given.
    if (!v.cipherListComplete) {
      frag.appendChild(el("p", "group-note",
        "This list is incomplete. The host stopped answering before enumeration ran out, "
        + "and suites are found strongest first, so what is missing is the weaker end."));
    }

    // One geometry for every cipher table, and a container that scrolls.
    //
    // Each version gets its own table, and until 2026-09-02 each sized its own
    // columns to its own contents: measured on a live report, "Key exchange"
    // began 92 pixels further right under TLS 1.2 than under TLS 1.3, and
    // "Cipher" 68 to the left. Two tables, one above the other, the same four
    // columns, and a reader's eye could not run down one of them. Nothing was
    // wrong with any row; the page simply could not be read the way a table
    // exists to be read.
    //
    // Declared widths make the columns the same everywhere, and a scrolling
    // container keeps them that way on a narrow screen instead of breaking a
    // forty-five character suite name across three lines.
    const table = el("table", "rows suites");

    // The geometry is declared on the columns, not left to the contents.
    //
    // A <colgroup> is the one place a table can be told how wide its columns
    // are before any row is read, and it is what makes two tables one above
    // the other line up. The stylesheet gives three of them a width and lets
    // the suite names take what is left.
    //
    // Written out one at a time rather than looped over a list, because the
    // test that checks every class the script writes has a rule behind it
    // reads class names out of el() calls. A class assembled from a variable
    // is invisible to it, and a column with no rule is a column with no
    // width.
    const group = el("colgroup");
    group.appendChild(el("col", "col-grade"));
    group.appendChild(el("col", "col-suite"));
    group.appendChild(el("col", "col-kex"));
    group.appendChild(el("col", "col-cipher"));
    table.appendChild(group);

    const head = el("tr");
    for (const label of ["Grade", "Suite", "Key exchange", "Cipher"]) {
      head.appendChild(el("th", null, label));
    }
    table.appendChild(el("thead")).appendChild(head);

    const body = el("tbody");
    for (const c of v.ciphers) {
      const row = el("tr");
      row.appendChild(el("td", markClass(c.verdict), c.verdict || "—"));
      // Marked so the stylesheet may break this column mid-word on a narrow
      // screen without doing the same to the short labels beside it.
      row.appendChild(el("td", "identifier", c.name));
      row.appendChild(el("td", "mark-faint", c.keyExchange || "—"));
      row.appendChild(el("td", "mark-faint", c.cipher || "—"));
      body.appendChild(row);
    }
    table.appendChild(body);
    frag.appendChild(el("div", "table-scroll")).appendChild(table);
  }

  // Labelled rather than left as prose.
  //
  // These sat under the table with nothing in front of them, and the key
  // exchange — the one measurement that costs the scanned server an extra
  // handshake — was read on a second visit rather than the first. The
  // certificate rows are found because they carry a label; these now do too.
  //
  // They stay with the suites and not with the certificate. A key exchange is
  // a property of the transport: the certificate's key is RSA 4096 and the
  // exchange is X25519MLKEM768, and filing one under the other teaches a
  // reader they are the same thing.
  const facts = el("dl", "pairs");
  let said = false;

  function fact(label, value, checked) {
    if (!value) return;
    facts.appendChild(el("dt", null, label));
    const dd = el("dd", null, value);
    const list = checkedList(checked);
    if (list) dd.appendChild(list);
    facts.appendChild(dd);
    said = true;
  }

  if (tls.preferenceKnown) {
    fact("Cipher order", tls.serverPreference
      ? "the server imposes its own"
      : "the client's, which lets an outdated client choose a weaker suite");
  }
  if (report && report.keyExchangeLine) {
    fact("Key exchange", report.keyExchangeLine);
  }
  // Services on the host that should not face the internet. Built by the
  // server, so both faces read the same line (R16).
  if (report && report.exposureLine) {
    fact("Exposed services", report.exposureLine, report.exposureChecked);
  }
  if (said) frag.appendChild(facts);

  return frag;
}

// The four states a reader has to be able to tell apart. Returns undefined
// when the report says nothing about revocation, so the row is left out
// entirely rather than filled with a guess.
// The revocation and transparency sentences used to be composed here, and only
// here. That put them out of reach of the terminal report, which showed
// neither, and out of reach of anything that could execute them: the
// revocation sentence went on saying "a status response was stapled" for a
// whole policy version after the service had begun parsing that response,
// matching it to the certificate, checking its freshness and verifying the
// issuer's signature.
//
// They are built in internal/policy now, arrive as report.revocationLine and
// report.transparencyLine, and are printed here unchanged. Do not compose a
// sentence in this file from facts the report already carries a sentence for:
// two renderers building one claim is how the two come to disagree. R16.

function certificate(cert, tls, issuance, stapling, report) {
  if (!cert || !Array.isArray(cert.chain) || !cert.chain.length) {
    return document.createDocumentFragment();
  }

  const leaf = cert.chain[0];
  const grade = cert.grade || {};

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Certificate"));

  const pairs = el("dl", "pairs");

  // A row with nothing in it says so, rather than not being drawn.
  //
  // This returned early on an empty value, so eight rows disappeared whenever
  // the answer was empty — and a row that is not there reads as a question
  // nobody had. "Logged" is the one that made the case: empty means nothing
  // searched the transparency logs, and a reader who could not see the row had
  // no way to tell that from "no other certificate exists for this name" (R4).
  //
  // A caller that means "this does not apply here" leaves the call out, which
  // is a decision at the call site rather than a silence in the helper.
  function pair(label, value, absent) {
    if (value === undefined || value === null || value === "") value = absent || "none";
    pairs.appendChild(el("dt", null, label));
    pairs.appendChild(el("dd", null, value));
  }

  pair("Subject", leaf.subject);
  pair("Issuer", leaf.issuer);
  // What the issuer says it checked. Next to the issuer because that is whose
  // claim it is, and above the dates because it is about how the certificate
  // came to exist rather than about how long it lasts.
  pair("Validation", leaf.validation, "not stated by the certificate");

  const from = (leaf.notBefore || "").slice(0, 10);
  const to = (leaf.notAfter || "").slice(0, 10);
  if (from && to) {
    const days = grade.daysRemaining;
    let life = from + " to " + to;
    if (typeof days === "number") {
      life += days >= 0 ? "  ·  " + days + " days left" : "  ·  expired " + (-days) + " days ago";
    }
    pair("Valid", life);
  }

  if (grade.validityDays) {
    pair("Lifetime", grade.validityDays + " days, limit at issuance " + grade.maxValidityDays + " days");
  }

  pair("Key", leaf.keyBits ? leaf.keyAlgorithm + " " + leaf.keyBits : leaf.keyAlgorithm);
  pair("Signature", leaf.signatureAlgorithm);

  pair("Names", (leaf.dnsNames || []).join(", "), "none");
  pair("Addresses", (leaf.ipAddresses || []).join(", "), "none");

  pair("Name match", cert.nameLine, "not checked");
  pair("Chain", cert.chain.length + (cert.trusted ? " certificates, trusted" : " certificates, not trusted"));

  // Each certificate above the leaf: which authority issued it, under which
  // root, and when each runs out. Composed in internal/policy, as the
  // terminal prints them (R16); here the name is set apart from the rest.
  for (const line of cert.chainLines || []) {
    pairs.appendChild(el("dt", null, ""));
    const dd = el("dd", "report-logged");
    const cut = line.indexOf(": ");
    if (cut > 0) {
      const head = el("span", "report-logged-head");
      head.appendChild(el("span", "report-logged-serial", line.slice(0, cut)));
      head.appendChild(el("span", null, line.slice(cut + 2)));
      dd.appendChild(head);
    } else {
      dd.textContent = line;
    }
    pairs.appendChild(dd);
  }

  // What Mozilla, Chrome, Microsoft and Apple make of the chain, in the words
  // certinfo wrote, which the terminal prints too (R16).
  if (cert.storesLine) pair("Stores", cert.storesLine);

  // What the certificate asks for, and what the handshake carried.
  //
  // Four states rather than a tick. "Not stapled" alone reads as a fault,
  // and for a certificate issued now it usually is not one: authorities are
  // no longer required to run OCSP, and several have stopped. The
  // distinction between a server that could staple and did not and one that
  // has nothing to staple is the whole content of this line.
  pair("Revocation", report && report.revocationLine, "not checked");

  // Issuance sits above transparency because the two are halves of one
  // question in the order they happen: who may obtain a certificate for this
  // name, and whether obtaining one leaves a record. A restriction is checked
  // when a certificate is issued; the logs record the result either way.
  //
  // It is on a line of its own rather than in the notes, which fold shut
  // under every verdict but ungraded. For a name with no CAA this is often
  // the most useful sentence in the report — one DNS record, nothing to break
  // by adding it — and a sentence nobody opens is a sentence nobody reads.
  pair("Issuance", issuance && issuance.line, "not read");

  // The accounts a bound authority is held to, one mark each, under the line
  // that counts them. The note under the report names them in a sentence, as
  // the terminal prints it (R16); here they are what a reader checks against
  // their own, so each is set where it can be read whole.
  for (const b of (issuance && issuance.bindings) || []) {
    if (!Array.isArray(b.accounts) || !b.accounts.length) continue;
    const held = el("dd", "report-held");
    held.appendChild(el("span", "report-held-label",
      (b.accounts.length === 1 ? "The account " : "The accounts ") + b.authority +
      (b.wildcard ? " may use for wildcards" : " may use")));
    const list = el("span", "report-list");
    for (const account of b.accounts) list.appendChild(el("span", "report-list-item", account));
    held.appendChild(list);
    pairs.appendChild(el("dt", null, ""));
    pairs.appendChild(held);
  }
  pair("Transparency", report && report.transparencyLine, "not read");

  // What the public logs hold for this name, where a deployment searched them.
  // Absent where none did, which is this one: the sentence is composed in
  // internal/policy and arrives empty when no search was made, so nothing here
  // decides whether to show it.
  pair("Logged", report && report.loggedLine,
    "not searched: the public logs were not asked what else exists for this name");

  // And the certificates that line counts, one under another, because a count
  // asking the reader to check a list is no use without the list. Composed in
  // internal/policy, as the terminal prints them (R16).
  //
  // Each is set from the entry the sentence was written from, where the
  // report carries it: the serial, the issuer and the dates on one line, the
  // names it covers as marks under them. Written as one sentence each, three
  // certificates were three lines of serials, distinguished names and comma
  // lists, and the names a reader needed to check were the hardest part to
  // find. A sentence with no entry behind it is shown as written.
  //
  // Each ends on how it compares with the one presented, from the same
  // policy clause the terminal prints at the end of the sentence, so the
  // reader does not have to compare authorities and names by eye.
  const entries = (report && report.logged && Array.isArray(report.logged.entries)) ? report.logged.entries : [];
  const resemblance = (report && Array.isArray(report.loggedResemblance)) ? report.loggedResemblance : [];
  ((report && report.loggedUnaccounted) || []).forEach((c, i) => {
    pairs.appendChild(el("dt", null, ""));
    const entry = entries.find((e) => e && e.serial && c.startsWith("serial " + e.serial + ","));
    if (!entry) {
      pairs.appendChild(el("dd", null, "· " + c));
      return;
    }
    const dd = el("dd", "report-logged");
    const head = el("span", "report-logged-head");
    head.appendChild(el("span", "report-logged-serial", entry.serial));
    head.appendChild(el("span", null, "issued by " + entry.issuer));
    head.appendChild(el("span", null, "valid " + String(entry.notBefore || "").slice(0, 10) +
      " to " + String(entry.notAfter || "").slice(0, 10)));
    dd.appendChild(head);
    const names = el("span", "report-list");
    for (const name of entry.names || []) names.appendChild(el("span", "report-list-item", name));
    dd.appendChild(names);
    if (typeof resemblance[i] === "string" && resemblance[i]) {
      dd.appendChild(el("span", "report-logged-resemblance", resemblance[i]));
    }
    pairs.appendChild(dd);
  });

  // The serial in the form the logged certificates above are listed in, so a
  // reader can tell whether one of them is this one.
  pair("Serial", leaf.serialHex, "not recorded in this report");
  pair("SHA-256", leaf.fingerprintSha256);

  frag.appendChild(pairs);
  return frag;
}

/*
  What was not measured, kept in proportion to how much it matters.

  A reader who is not told what was skipped will read silence as a clean
  result, so this is never omitted. But three paragraphs of caveat under a
  clean report is its own kind of noise, and a reader who meets it every time
  stops reading it — which produces the same silence by a longer route.

  So the summary is always visible and always counts them, and the detail
  opens on request. Except where it is the whole story: a report that graded
  nothing has nothing else to say, and there the limits are the finding.

  That exception was once extended to an insecure verdict as well, and the
  reasoning above never covered it. A report that graded a server insecure
  has findings, a version table, a cipher list and a certificate: the limits
  are a footnote there exactly as they are under a strong verdict, and
  opening them by default said otherwise. Nothing is hidden either way —
  the count sits in the summary line whether the block is open or shut.
*/
// What a weak or insecure verdict means.
//
// Written here and in internal/policy, and compared by a test that reads both
// — the same arrangement as the section titles below. A sentence about how
// grading works, said in two different words on two faces of one report,
// would be worse than not saying it at all.
const WORST_CASE = "Worst case: the weakest thing found sets the verdict, " +
  "because it is the one an attacker would use.";

// The three sections, their order and their words. The terminal report reads
// the same three from noteSections in cmd/denyfirst-scan, and the two are
// compared by a test: a reader holding one output beside the other should not
// have to work out that they match.
const NOTE_SECTIONS = [
  {
    kind: "observed",
    title: "Observed",
    box: "notes-section",

    // Folded, and this is safe because of what is in it.
    //
    // Every fact an observation describes is already on the face of the
    // report: the key exchange line says the hybrid was declined, the
    // revocation row says nothing was stapled, the issuance row says no CAA
    // was found, the certificate rows carry the names and the timestamps.
    // What folds is the reasoning behind them, which is the same on every
    // report and is what made this block five paragraphs long.
    //
    // The count stays in the summary, so folding is not hiding. The
    // coverage line under the verdict says how much of the picture the scan
    // reached, which is the thing a reader would otherwise open this for.
    open: false,
    // Not "findings". The report uses that word for a rule that was broken
    // and says, three lines above this, that there were none — so "5 findings
    // not graded" asked a reader to hold two meanings of one word at once.
    one: "1 measured, not graded",
    many: (n) => n + " measured, not graded",
  },
  {
    kind: "unsettled",
    title: "Not established for this host",
    box: "notes-section notes-limits",
    // Open. What a scan could not establish is the half of a report a reader
    // has to see to know what the rest is worth (R4), and it is short: a
    // sentence for each thing, not the reasoning that folds above.
    open: true,
    one: "1 limit",
    many: (n) => n + " limits",
  },
];

// The third kind is a link, not a section.
//
// A standing limit is the same on every report, so showing them all on every
// report is how they stop being read — and sitting beside a host's own
// shortcomings they read as though they were some. They are on one page, and
// the report says how many there are and points at it, so moving them is not
// hiding them.
// Which page, per check: what a TLS handshake cannot establish is not what a
// header check cannot establish, and a link that pointed at one from the other
// would send a reader to limits that are not theirs. So each builder passes its
// own. It was read from the page once, which held while a page ran one check;
// the Porch page runs three, and its Reach and Mail reports pointed at the
// limits of Transport.

// notes renders each kind under its own heading.
//
// Until 2026-09-01 there was one heading — "What this did not measure" — over
// everything that was not a finding. A scan of kapitalbank.az put eleven
// sentences under it, of which three were limits of that scan. Among the rest
// was a post-quantum key exchange that had been measured and had passed, and
// a stapled revocation response that had been read and verified. A reader who
// trusted the heading concluded the scanner had established almost nothing,
// which is the opposite of what the report contained.
//
// Both sections fold. Every fact in them is already on the face of the
// report, so what folds is the reasoning; the counts stay in the summaries,
// and an ungraded verdict opens them because then there is nothing else.
function notes(list, verdict, methodPage) {
  const frag = document.createDocumentFragment();
  if (!list || !list.length) return frag;

  for (const section of NOTE_SECTIONS) {
    const chosen = list.filter((n) => n && n.kind === section.kind);
    if (!chosen.length) continue;

    // A literal class, not one built from the kind. internal/web reads the
    // classes this script adds straight out of its source and checks each one
    // is styled; a class assembled at runtime is invisible to that check, and
    // an unstyled class is exactly what it exists to catch. The three sections
    // differ by their words and by which of them opens, not by their colour.
    const box = el("details", section.box);
    // An ungraded verdict means something was not reached, so the reasons are
    // opened rather than left behind a summary.
    box.open = section.open || verdict === "ungraded";

    const head = el("summary", "notes-head");
    head.appendChild(el("span", "notes-title", section.title));
    head.appendChild(el("span", "notes-count",
      chosen.length === 1 ? section.one : section.many(chosen.length)));
    box.appendChild(head);

    const ul = el("ul", "notes");
    for (const note of chosen) ul.appendChild(el("li", null, note.text));
    box.appendChild(ul);

    frag.appendChild(box);
  }

  const standing = list.filter((n) => n && n.kind === "standing");
  if (standing.length) {
    const p = el("p", "notes-method");
    // Two of the four limits are conditional, so a report can carry one: a
    // host that speaks only TLS 1.2 and returns no transparency receipts
    // leaves exactly one, and the page said "1 limits".
    p.appendChild(document.createTextNode(standing.length === 1
      ? "1 limit of this method applies to every scan and is the same here as anywhere. "
      : standing.length + " limits of this method apply to every scan and are the same here as anywhere. "));

    const a = el("a", "notes-method-link", "What this can see, and what it cannot");
    a.href = methodPage;
    p.appendChild(a);

    frag.appendChild(p);
  }

  return frag;
}

function failure(message, detail) {
  const box = el("div", "failure");
  box.appendChild(el("p", null, message));
  if (detail) box.appendChild(el("p", null, detail));
  return box;
}

// ── Rendering ───────────────────────────────────────────────────────────

function show(node) {
  clear(result);
  result.hidden = false;
  result.appendChild(node);
}

function buildTLS(data) {
  // Read once. data.verdict is absent rather than "ungraded" when nothing was
  // graded, so every section that cares has to be given the resolved value —
  // passing data.verdict straight through would hand them undefined at
  // exactly the moment the distinction matters most.
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(versions(data.tls));
  frag.appendChild(ciphers(data.tls, data));
  frag.appendChild(legacy(data.tls));
  frag.appendChild(addresses(data.tls));
  frag.appendChild(certificate(data.certificate, data.tls, data.issuance, data.stapling, data));
  frag.appendChild(notes(data.notes, verdict, CHECKS.tls.methodPage));
  return frag;
}

/*
  The web report: two chains, drawn the same way.

  A chain is the sequence of addresses a browser would be sent through,
  starting at the secure address and starting again at the plaintext one. It is
  the whole evidence behind the verdict, so it is on the face of the report
  rather than folded away — a reader who cannot see where a site sent them
  cannot check the grade against anything.

  Both chains get identical columns, because they are the same measurement
  begun at two addresses and a reader comparing them should not have to work
  out which column moved (W3).
*/

// hopTransport says how a hop was made, in a word.
//
// In words rather than only in colour. A reader who cannot distinguish the two
// colours, or who prints the page, has to be able to read the one fact this
// column exists for (W6).
function hopTransport(hop) {
  if (hop.tls) return "TLS";
  return "plaintext";
}

// hopOutcome is what came back, or why nothing did.
//
// A hop that failed is not a response with no headers, and the difference
// decides a verdict rather than a detail: a host answering 200 in the clear is
// insecure, and a host with nothing listening on port 80 is the safest
// arrangement there is (R23). So a failure says so in its own words rather
// than appearing as a blank status.
function hopOutcome(hop) {
  const cell = el("td", hop.error ? "mark-faint" : null);
  if (hop.error) {
    cell.appendChild(el("span", null, "no response"));
    // The reason is a phrase webprobe wrote, never a string from the standard
    // library, so it carries no address of this machine (I6). It still reaches
    // textContent rather than a parser, like everything else here.
    cell.appendChild(el("p", "row-note", hop.error));
    return cell;
  }
  cell.appendChild(el("span", null, String(hop.status || "—")));
  return cell;
}

function chain(title, c) {
  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle(title));

  if (!c || !Array.isArray(c.hops) || !c.hops.length) {
    // Nothing attempted is not nothing found. Saying so is the same rule R4
    // states for a verdict, applied to a table.
    frag.appendChild(el("p", "plain", "Nothing was attempted at this address."));
    return frag;
  }

  const table = el("table", "rows chain");

  // The geometry is declared on the columns, exactly as the cipher tables
  // declare theirs and for the same reason.
  //
  // Two chains are drawn one above the other and the comment at the top of
  // this section says they get identical columns — which they did not. Each
  // table sized itself to its own contents, and the two chains never hold the
  // same contents: the secure one carries long https:// addresses and the
  // plaintext one usually a single short hop. So "Response" sat at the right
  // edge above and near the middle below, and a reader comparing the two had
  // to find each column again (W3).
  const group = el("colgroup");
  group.appendChild(el("col", "col-address"));
  group.appendChild(el("col", "col-transport"));
  group.appendChild(el("col", "col-response"));
  table.appendChild(group);

  const head = el("tr");
  for (const label of ["Address", "Transport", "Response"]) {
    head.appendChild(el("th", null, label));
  }
  table.appendChild(el("thead")).appendChild(head);

  const body = el("tbody");
  for (const hop of c.hops) {
    const row = el("tr");
    // The address as it was requested. Attacker-chosen after the first hop —
    // every one after it came out of a Location header — so it is text in a
    // cell and never a link: a redirect target this scanner declined to follow
    // must not become something a reader can click.
    //
    // Marked so the stylesheet may break it mid-word: with the columns
    // declared, an address longer than its column has to go somewhere, and
    // wrapping inside the cell is the one option that does not move the two
    // columns beside it.
    row.appendChild(el("td", "address", hop.url || "—"));
    row.appendChild(el("td", null, hopTransport(hop)));
    row.appendChild(hopOutcome(hop));
    body.appendChild(row);
  }
  table.appendChild(body);
  frag.appendChild(table);

  // Where a chain stopped, and whether stopping was a decision or a failure.
  // A reader who cannot tell those apart cannot interpret the chain at all
  // (N7).
  if (c.truncated) {
    frag.appendChild(el("p", "group-note",
      "The redirect limit was reached with another address still waiting, so this chain is " +
      "incomplete and nothing should be concluded from where it stops."));
  }
  if (c.stopped) {
    frag.appendChild(el("p", "group-note", "This chain was not followed further: " + c.stopped));
  }

  return frag;
}

function chains(observed) {
  const frag = document.createDocumentFragment();
  if (!observed) return frag;

  frag.appendChild(chain("Reached over HTTPS", observed.secure));
  frag.appendChild(chain("Reached over plaintext", observed.plain));

  // The user agent is not drawn. It is the same on every report, so it is a
  // line about this program rather than about the server, and the method
  // page states it with everything else that was sent; the report's limits
  // line links there. The field stays in the JSON, which is where a saved
  // report says how it was obtained, and the terminal never printed it.
  return frag;
}

function buildWeb(data) {
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(declared(data.declared));
  frag.appendChild(chains(data.observed));
  frag.appendChild(notes(data.notes, verdict, CHECKS.web.methodPage));
  return frag;
}

/*
  The mail report: what the zone says, and what it costs to evaluate.

  Two rows of evidence rather than a chain, because there is no chain — nothing
  was connected to. The lookup count is on the face of the report rather than
  only in the notes, since it is the number this check exists for: a domain at
  nine of ten is one provider away from switching its own policy off, and no
  other tool an operator runs will tell them.
*/

// buildDNS draws what a domain's own DNS publishes, and what the rules made of
// it.
//
// Every sentence here is written by this program from values it read, never
// pasted from the zone: a record is text chosen by whoever is being measured.
// The two places a published value appears as it stands are a server's address
// and the name an alias points at, both of which a reader needs exactly.
function buildDNS(data) {
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(published(data.observed));
  frag.appendChild(delegation(data.observed));
  frag.appendChild(notes(data.notes, verdict, CHECKS.dns.methodPage));
  return frag;
}

// published is the table a person opens this check for: what the name answers
// with today.
function published(facts) {
  const frag = document.createDocumentFragment();
  if (!facts) return frag;

  frag.appendChild(sectionTitle("What the name publishes"));

  const table = el("table", "grid");
  const body = el("tbody");
  const row = (name, value, mark) => {
    const tr = el("tr");
    tr.appendChild(el("th", null, name));
    tr.appendChild(el("td", mark ? markClass(mark) : null, value));
    body.appendChild(tr);
  };

  // Two kinds, two rows, and "none" on the row that found nothing: merged,
  // a reader cannot tell a name with no IPv6 from one nobody asked about.
  if (facts.addressReason) {
    row("Addresses", "not read: " + facts.addressReason);
  } else {
    row("IPv4 (A)", listOrNone(facts.ipv4));
    row("IPv6 (AAAA)", listOrNone(facts.ipv6));
  }
  // The name and its name servers on IPv6, built by the server (R16).
  if (facts.ipv6Line) row("IPv6", facts.ipv6Line);

  if (facts.aliasReason) {
    row("Alias (CNAME)", "not read: " + facts.aliasReason);
  } else if (!facts.alias) {
    row("Alias (CNAME)", "none");
  } else {
    row(
      "Alias (CNAME)",
      facts.alias + (facts.aliasTargetExists ? "" : ", which does not exist"),
      facts.aliasTargetExists ? null : "weak",
    );
  }

  if (facts.soaFound) {
    row("Zone (SOA)", "begins here, serial " + facts.soaSerial);
    row("Primary", facts.soaPrimary);
    // The zone's timers and its contact, read with the serial and shown only
    // in a folded note until now. Built by the server (R16).
    if (facts.timersLine) row("Timers (SOA)", facts.timersLine);
    if (facts.soaMailbox) row("Mailbox (SOA)", facts.soaMailbox);
  } else if (facts.soaReason) {
    // A record that could not be read is not a name inside a zone (R4).
    row("Zone (SOA)", "not read: " + facts.soaReason);
  } else {
    row("Zone (SOA)", "begins above this name");
  }

  // Records that could not be read are not a name publishing none (R4).
  const text = facts.text || [];
  row("Text records (TXT)", facts.textReason ? "not read: " + facts.textReason
    : text.length === 0 ? "none" : text.length + (text.length === 1 ? " record" : " records"));

  row("DNSSEC (DS)", dnssecLine(facts), dnssecMark(facts));

  // What the registry holds: when the domain runs out and whether it is
  // locked against transfer. Built by the server, so both faces read the
  // same line (R16).
  if (facts.registrationLine) row("Registration", facts.registrationLine);

  // Whether the routes to the addresses above, and to the name servers', are
  // signed (RPKI). Also built by the server.
  if (facts.routesLine) row("Routes (RPKI)", facts.routesLine);

  // The algorithm by the name an operator's own interface uses, and how
  // absent names are proved — both facts about a signed zone, neither a
  // verdict about it.
  if (facts.signed) {
    const names = (facts.keys || []).map(k => k.name || ("algorithm " + k.algorithm));
    // Each key by its tag and what it signs, and each digest the parent holds
    // for one, by the hash: the two halves of the chain, built by the server.
    // The keys line names the algorithm too, so the algorithm alone is said
    // only for a result from before the server built that line.
    if (names.length && !facts.keysLine) row("Signed with (DNSKEY)", [...new Set(names)].join(", "));
    if (facts.keysLine) row("Keys (DNSKEY)", facts.keysLine);
    if (facts.digestLine) row("Digests (DS)", facts.digestLine);
    // The date, on its own row. It is the one fact in this block that becomes
    // wrong by itself, while nobody changes anything.
    if (facts.signatureRead && facts.signatureExpires) {
      row("Signature (RRSIG)", signedOn(facts.signatureInception) + "runs out " + facts.signatureExpires.slice(0, 10) +
        ", made by key " + facts.signatureKeyTag);
    }
    if (facts.nsec3Read) row("Absent names (NSEC3)", absenceLine(facts));
  }

  table.appendChild(body);
  frag.appendChild(table);
  frag.appendChild(textRecords(text));
  return frag;
}

// signedOn says when a signature was made, where the report carries it, ahead
// of when it runs out: the two together are the window a validator accepts.
function signedOn(inception) {
  return inception && !String(inception).startsWith("0001-01-01") ? "signed " + String(inception).slice(0, 10) + ", " : "";
}

// listOrNone writes a list, or says there was none. Empty is a fact here: the
// lookup happened and found nothing.
function listOrNone(values) {
  return (values || []).length === 0 ? "none" : values.join(", ");
}

// textRecords draws what the name publishes as text, as published.
//
// Every other line of a report is written by this program. These are the only
// ones chosen by whoever is being measured, so they are set apart and labelled
// as theirs: a record made to read like advice should never be mistaken for a
// sentence this program wrote.
//
// Bounded twice, because a TXT record is whatever somebody put there: at most
// eight records, and each cut to a length that still shows what it is.
function textRecords(records) {
  const frag = document.createDocumentFragment();
  if (records.length === 0) return frag;

  frag.appendChild(sectionTitle("Text records, as published"));
  frag.appendChild(el("p", "section-note",
    "Written by whoever runs this domain, not by this report. Shown as they are, shortened where long."));

  const list = el("pre", "work-code");
  const shown = records.slice(0, 8);
  list.textContent = shown
    .map(record => (record.length > 120 ? record.slice(0, 120) + "…" : record))
    .join("\n");
  frag.appendChild(list);

  if (records.length > shown.length) {
    frag.appendChild(el("p", "section-note", "and " + (records.length - shown.length) + " more"));
  }
  return frag;
}

// absenceLine says how a signed zone proves a name does not exist: hashed, at
// what cost, or plainly — which is what lets anybody list the zone.
function absenceLine(facts) {
  if (!facts.nsec3) return "named plainly, so the zone can be listed";
  const iterations = facts.nsec3Iterations || 0;
  return iterations === 0 ? "hashed" : "hashed, " + iterations + " extra times";
}

// dnssecLine says what the chain is, in the order a reader asks it: whether it
// is signed at all, and then whether it holds.
function dnssecLine(facts) {
  // The chain belongs to a zone, and at a name inside one nothing about it was
  // asked. "Not signed" there is a claim about a zone this never looked at,
  // and the zone above is often signed (R4).
  if (!facts.apex) return "not read: the chain belongs to the zone above this name";
  if (!facts.signed) return "not signed";
  if (facts.chainReason) return "not checked: " + facts.chainReason;
  if (facts.chainMatched && facts.signatureFault) {
    return "signed, and the parent's digest matches a key here, but " + facts.signatureFault;
  }
  if (facts.chainMatched && facts.signaturesVerified) {
    return "signed; the parent's digest matches a key here, and the signatures verify";
  }
  if (facts.chainMatched && facts.signatureCheckReason) {
    return "signed, and the parent's digest matches a key here; signatures not checked: " + facts.signatureCheckReason;
  }
  if (facts.chainMatched) return "signed, and the parent's digest matches a key here";
  if ((facts.keys || []).length === 0) return "anchored at the parent, and no key is published here";
  return "anchored at the parent, and no key here matches its digest";
}

function dnssecMark(facts) {
  if (!facts.signed || facts.chainReason) return null;
  if (facts.chainMatched && facts.signatureFault) return "insecure";
  return facts.chainMatched ? "strong" : "insecure";
}

// declared draws what the response a visitor lands on said about itself.
//
// Every row, whether or not there is an answer in it. Thirteen headers were
// measured on every scan and shown on none, so a report of a site that declares
// a content policy looked exactly like a report of one that declares nothing —
// and the second is the one an operator needs to be told about.
//
// Nothing here is marked: no document requires most of it, so none of it is
// graded, and a colour would say otherwise.
function declared(rows) {
  const frag = document.createDocumentFragment();
  if (!rows || rows.length === 0) return frag;

  frag.appendChild(sectionTitle("What the site sends"));

  const table = el("table", "grid");
  const body = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    tr.appendChild(el("th", null, row.label));
    const td = el("td", null, row.says);
    // A row that counted something carries what it counted (R4).
    const list = checkedList(row.checked);
    if (list) td.appendChild(list);
    tr.appendChild(td);
    body.appendChild(tr);
  }
  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

// checkedList draws what a line counted, one item each, folded under the line
// until asked for: the files a site was asked for, the ports a host was asked
// on. The words are the server's (internal/policy.Checked), so the page and
// the terminal say the same thing (R16); nothing is parsed as markup.
//
// Folded, because the line already answers the question and the list is
// there for the reader who asks what it counted. On paper it is drawn open,
// since nobody can unfold a sheet (see the print handlers below). A report
// from before the list existed has none, and draws only the line.
function checkedList(items) {
  if (!Array.isArray(items) || items.length === 0) return null;
  const details = el("details", "checked-list");
  details.appendChild(el("summary", null, items.length + " checked"));
  const grid = el("div", "checked-grid");
  for (const item of items) {
    if (!item || typeof item.item !== "string") continue;
    const cell = el("div", item.found ? "checked-item is-found" : "checked-item");
    // A port reads with its service on one line, "445 SMB"; a path is long,
    // so what it is goes under it, the same way in every cell.
    const name = el("span", /^\d+$/.test(item.item) ? "checked-name is-inline" : "checked-name");
    name.appendChild(el("code", null, item.item));
    if (item.what) name.appendChild(el("span", "checked-what", item.what));
    cell.appendChild(name);
    cell.appendChild(el("span", "checked-state", item.state || ""));
    grid.appendChild(cell);
  }
  details.appendChild(grid);
  return details;
}

// delegation draws the servers the zone is answered by, one row each, so that a
// name with no address is visible beside the ones that have them.
function delegation(facts) {
  const frag = document.createDocumentFragment();
  if (!facts || !facts.apex) return frag;

  frag.appendChild(sectionTitle("Where the zone is answered"));

  if (facts.nsReason) {
    frag.appendChild(el("p", "section-note", "The delegation was not read: " + facts.nsReason));
    return frag;
  }

  const servers = facts.nameServers || [];
  if (servers.length === 0) {
    frag.appendChild(el("p", "section-note", "The zone names no server."));
    return frag;
  }

  const table = el("table", "grid");
  const head = el("thead");
  const headRow = el("tr");
  for (const name of ["Server (NS)", "Addresses", "Serial (SOA)"]) headRow.appendChild(el("th", null, name));
  head.appendChild(headRow);
  table.appendChild(head);

  const body = el("tbody");
  for (const server of servers) {
    const tr = el("tr");
    tr.appendChild(el("td", null, server.name));

    const addresses = server.addresses || [];
    let text = addresses.join(", ");
    let mark = null;
    if (server.asked && !server.authoritative) {
      text = "does not answer for this zone";
      mark = "weak";
    } else if (server.transfer) {
      text = addresses.join(", ") + " — hands out the whole zone to anybody";
      mark = "faint";
    } else if (server.recursion) {
      text = text + " — answers for other domains too";
      mark = "weak";
    } else if (server.alias) {
      text = "an alias for " + server.alias;
      mark = "weak";
    } else if (server.reason) {
      text = "not read: " + server.reason;
    } else if (addresses.length === 0) {
      text = "resolves to nothing";
      mark = "weak";
    }
    tr.appendChild(el("td", mark ? markClass(mark) : null, text));
    // The serial each server answered with. Servers that disagree are serving
    // different copies of the zone, which only this column shows.
    tr.appendChild(el("td", server.serialRead ? null : "mark-faint",
      server.serialRead ? String(server.serial) : "not read"));
    body.appendChild(tr);
  }
  table.appendChild(body);
  frag.appendChild(table);

  // Not where a server's addresses went unread: the count is then a lower
  // bound, and "they fail together" would be a guess.
  const networks = facts.networks || 0;
  if (servers.length > 1 && networks > 0 && !servers.some((s) => s.reason)) {
    frag.appendChild(el("p", "section-note",
      // What is counted, said: an IPv4 /24 and an IPv6 /48 each count once,
      // so blocks one operator holds count separately. "10 networks" of one
      // provider read as ten independent ones until 2026-10-25.
      networks === 1
        ? "Every address above is in one network (one IPv4 /24 or IPv6 /48), so they fail together."
        : "Their addresses are in " + networks + " networks, counting each IPv4 /24 and IPv6 /48 as one; " +
          "blocks one operator holds count separately."));
  }

  frag.appendChild(el("p", "section-note", parentSays(facts)));

  // What the zone above hands out as each server's address, where it hands out
  // anything. Only a server inside the zone it serves has glue, so this is a
  // row about those and about nothing else.
  for (const server of servers) {
    if (!server.glueRead) continue;
    frag.appendChild(el("p", "section-note",
      "The zone above hands out " + listOrNone(server.glue) + " for " + server.name + "."));
  }
  return frag;
}

// parentSays reports the other claim about this delegation: the list the zone
// above hands out, which is the one a resolver starting at the root follows.
//
// Unmarked, like the note above it: the finding carries the grade, and a
// sentence that repeats it in colour says the same thing twice.
function parentSays(facts) {
  const above = facts.parent || "the zone above this one";
  if (facts.parentReason) return "The zone above this one was not read: " + facts.parentReason;
  if (!facts.parentAsked) return "The zone above this one was not asked which servers it delegates to.";

  const atParent = facts.onlyAtParent || [];
  const atZone = facts.onlyAtZone || [];
  if (atParent.length === 0 && atZone.length === 0) {
    return "Asked directly, " + above + " hands out the same servers.";
  }

  const parts = [];
  if (atParent.length > 0) parts.push("hands out " + atParent.join(", ") + " as well");
  if (atZone.length > 0) parts.push("does not hand out " + atZone.join(", "));
  return "Asked directly, " + above + " " + parts.join(", and ") + ".";
}
// dmarcFrom names the domain above whose record applies, where the name
// checked publishes none of its own (porch-mail-v5).
function dmarcFrom(facts) {
  return facts.dmarcFrom ? ", from " + facts.dmarcFrom : "";
}

// saysReportTo is where a DMARC record asks for its aggregate reports, and
// what was established about each destination outside the domain.
//
// The tag was a boolean on this page until 2026-09-28 — reports are asked for,
// or they are not — which answered neither question an operator has of it.
// Where they go decides whether the destination is still one they use; whether
// it agreed decides whether anything arrives at all, because RFC 7489 §7.1
// forbids a receiver from sending reports outside the domain until the
// destination publishes a record accepting them.
//
// A mailbox appears where the service was told to send one, and the domain
// always. Nothing here is drawn from the presence of the mailbox, so a report
// that withheld it reads the same.
function saysReportTo(facts) {
  const dest = facts.dmarcReportTo || {};
  const places = dest.destinations || [];
  if (!dest.asked || !places.length) return "";

  const said = places.map((d) => {
    const at = d.mailbox || d.domain;
    if (!d.external) return at + " (inside this domain)";
    if (d.reason) return at + " (not established: " + d.reason + ")";
    if (d.authorised) return at + " (agreed)";
    return at + " (has not agreed, so it receives none)";
  });

  return dest.dropped
    ? said.join(", ") + ", and " + dest.dropped + " more this check did not read"
    : said.join(", ");
}

function buildMail(data) {
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(zone(data.observed));
  frag.appendChild(notes(data.notes, verdict, CHECKS.mail.methodPage));
  return frag;
}

// zone draws what the three lookups established.
//
// Every row a reader acts on is written by this program from booleans and
// counts, never pasted from the zone: a record's text is chosen by whoever is
// being measured, and the sentences a reader acts on should not be. The one
// exception is labelled as what it is — the Record rows, which carry the zone's
// own text to the person the zone belongs to and to nobody else.
function zone(facts) {
  const frag = document.createDocumentFragment();
  if (!facts) return frag;

  frag.appendChild(sectionTitle("What the zone says"));

  const table = el("table", "grid");
  const body = el("tbody");

  // A record as the zone publishes it is text somebody copies, so it is set
  // in the monospace, as a record is wherever else it is shown.
  const row = (name, value, mark, record) => {
    const tr = el("tr");
    tr.appendChild(el("th", null, name));
    const td = el("td", [mark ? markClass(mark) : "", record ? "dns-record" : ""].join(" ").trim() || null, value);
    tr.appendChild(td);
    body.appendChild(tr);
  };

  // SPF, and the three states that are not "a policy was read".
  if (facts.spfReason) {
    row("SPF", "not read: " + facts.spfReason);
  } else if (!facts.spfRecords) {
    row("SPF", "none published");
  } else if (facts.spfRecords > 1) {
    row("SPF", facts.spfRecords + " records, which is a permanent error", "insecure");
  } else {
    row("SPF", "ends in " + (facts.spfAll || "no ") + "all");
    row(
      "Lookups",
      (facts.spfLookupsAtLeast ? "at least " : "") + facts.spfLookups + " of the ten RFC 7208 allows",
      facts.spfLookupLimit ? "insecure" : null,
    );
    // The names the policy asks for that answer nothing. RFC 7208 allows two
    // before the policy fails, and a count of them was measured on every
    // report and shown only when it went over.
    row("Void lookups", facts.spfVoidLookups + " of the two RFC 7208 allows",
      facts.spfVoidLimit ? "weak" : null);
  }
  // The record itself, where the report is read by the person the domain
  // belongs to. The service decides that and leaves the field empty otherwise,
  // and the terminal prints the same field under the same row (R16).
  if (facts.spfRecord) row("Record", facts.spfRecord, null, true);

  if (facts.dmarcReason) {
    row("DMARC", "not read: " + facts.dmarcReason);
  } else if (!facts.dmarcRecords) {
    row("DMARC", "none published, here or above", "weak");
  } else if (facts.dmarcRecords > 1) {
    row("DMARC", facts.dmarcRecords + " records" + dmarcFrom(facts) + ", so a receiver applies none", "weak");
  } else if (!["none", "quarantine", "reject"].includes(facts.dmarcPolicy)) {
    row("DMARC", "published" + dmarcFrom(facts) + ", and names no policy", "weak");
  } else {
    row("DMARC", "p=" + facts.dmarcPolicy + " at " + (facts.dmarcPercent || 0) + "%" + dmarcFrom(facts),
      facts.dmarcPolicy === "none" ? "weak" : null);
  }
  if (facts.dmarcRecord) row("Record", facts.dmarcRecord, null, true);

  // Where the aggregate reports go, under the policy that asks for them.
  //
  // Each destination carries its own state rather than the row carrying a
  // total: one that agreed, one that has published nothing and therefore
  // receives nothing, and one whose authorisation could not be read are three
  // different things to do about (R4, RFC 7489 §7.1).
  const reportTo = saysReportTo(facts);
  if (reportTo) row("Reports to", reportTo);

  // A record that could not be read is not a record the domain lacks (R4).
  row("TLS-RPT", facts.tlsReportingReason ? "not read: " + facts.tlsReportingReason
    : facts.tlsReporting ? "yes" : "no");
  if (facts.tlsRptRecord) row("Record", facts.tlsRptRecord, null, true);

  // Signing keys, and which names were looked under.
  //
  // Nothing found is never drawn as "no DKIM". DNS cannot list what is beneath
  // a name, so a scan only ever looked where it was told to look, and the
  // difference between "these names hold nothing" and "this domain publishes no
  // key" is the whole honesty of the section (R4).
  if (facts.dkimLooked) {
    const keys = facts.dkimKeys || [];
    const found = keys.filter(k => k.found);
    // A selector whose lookup failed is not one that holds no key: until
    // 2026-10-26 a resolver that answered none of them drew "none at the
    // selectors tried" here, while the notes below said they went unread.
    const unread = keys.filter(k => k.reason).length;
    const notRead = unread ? "; " + unread + " could not be read" : "";

    if (found.length) {
      row("DKIM", found.map(k => k.selector + " (" + k.describes + ")").join(", ") + notRead);
    } else if (unread === keys.length) {
      row("DKIM", "not read: none of the " + keys.length + " selectors tried could be read");
    } else if (unread) {
      row("DKIM", "none at the " + (keys.length - unread) + " of the " + keys.length +
        " selectors tried that answered" + notRead);
    } else {
      row("DKIM", "none at the " + keys.length + " selectors tried");
    }
  } else {
    row("DKIM", "not checked: a selector has to be named");
  }


  // Where the mail goes, and what protects it there.
  //
  // Three states kept apart on every line, because the difference is the whole
  // value: a domain with no DANE, a domain whose DANE could not be read, and a
  // domain that accepts no mail at all are three answers a reader acts on
  // differently, and a table that drew them alike would be worse than silent.
  // Whatever the MX row says, the rows under it are still drawn.
  //
  // Three of these four used to end the block, so a domain whose MX lookup
  // failed, or that accepts no mail, was shown no MTA-STS row and no DANE row
  // at all — and MTA-STS is a separate lookup at a separate name that may well
  // have answered. A row that is not there reads as a question nobody had.
  const hosts = facts.mxHosts || [];
  if (facts.mxReason) {
    row("MX", "not read: " + facts.mxReason);
  } else if (facts.nullMX) {
    row("MX", "null MX: the domain accepts no mail");
  } else if (!facts.mxRead) {
    row("MX", "not read");
  } else {
    row("MX", hosts.length ? hosts.join(", ") : "none published");
    const aliased = facts.mxAliases || [];
    if (aliased.length) row("MX alias", aliased.join(", ") + ": a name RFC 2181 says carries an address", "weak");
    // Built by the server, so both faces read the same line (R16).
    if (facts.mxIPv6Line) row("MX IPv6", facts.mxIPv6Line);
  }

  row("MTA-STS", stsSays(facts));
  row("DANE", daneSummary(facts));
  if (facts.daneUnread) {
    row("DANE", facts.daneUnread + " could not be read");
  }

  // What each exchanger answered when asked for encryption, in the words the
  // terminal uses (R16). Where none was spoken to, why — including when even
  // the reason is missing, which used to draw nothing at all.
  if (hosts.length) {
    if (facts.exchangersContacted) {
      for (const x of facts.exchangers || []) {
        row("STARTTLS", x.host + ": " + exchangerSays(x));
      }
      for (const x of facts.exchangers || []) {
        if (!x.relayAsked && !x.relayReason) continue;
        row("RELAY", x.host + ": " + relaySays(x), x.relayAccepted ? "insecure" : null);
      }
      for (const x of facts.exchangers || []) {
        if (!x.legacyAsked && !x.legacyReason) continue;
        row("LEGACY", x.host + ": " + legacySays(x), x.legacyAccepted ? "weak" : null);
      }
      for (const b of facts.daneBindings || []) {
        row("DANE", b.host + ": " + daneSays(b));
      }
      // Built by the server, so both faces read the same line (R16), and
      // only where a greeting was read.
      for (const x of facts.exchangers || []) {
        if (x.softwareLine) row("SOFTWARE", x.host + ": " + x.softwareLine);
      }
    } else {
      row("STARTTLS", "not measured: " + (facts.exchangersReason || "this scan did not contact them"));
    }
  }

  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

// What one exchanger's STARTTLS row says.
//
// The same five states and the same words as exchangerLine in the command line,
// because a reader comparing the two faces of one report should find one set of
// facts (R16).
function exchangerSays(x) {
  if (!x.measured && x.connectTimedOut) return "not measured: port 25 could not be reached from here";
  if (!x.measured) return "not measured: " + x.reason;
  if (!x.offered) return "not offered";
  if (!x.upgraded) return "offered, not negotiated: " + x.reason;
  if (!x.trusted) return x.version + " " + x.suite + ", certificate does not verify: " + x.certificateReason;
  if (!x.nameMatches) return x.version + " " + x.suite + ", certificate does not name this exchanger";
  return x.version + " " + x.suite + ", certificate verifies" +
    (x.expires ? ", runs out " + String(x.expires).slice(0, 10) : "");
}

// What the relay question found, in the words the terminal uses (R16).
//
// Three states and never two: a server that agreed to forward for a domain it
// does not serve, one that refused, and one where the answer was not
// established — which is not a refusal (R4).
function relaySays(x) {
  if (x.relayAccepted) return "forwards mail for a domain it does not serve";
  if (x.relayAsked) return "refuses to forward for other domains";
  return "not established: " + x.relayReason;
}

// Whether the exchanger still speaks TLS 1.1 or older to a sender that offers
// nothing newer, in the words the terminal uses (R16). Asked and not answered
// is not a refusal (R4).
function legacySays(x) {
  if (x.legacyAccepted) return "accepts " + x.legacyVersion + " from a sender offering nothing newer";
  if (x.legacyAsked && !x.legacyReason) return "refuses TLS 1.1 and older";
  return "not established: " + x.legacyReason;
}

// What one exchanger's DANE records made of its certificate.
//
// The same words as daneLine in the command line (R16), and the same note when
// the resolver did not report the records validated: it decides whether a sender
// acts on any of it.
function daneSays(b) {
  let line;
  if (b.outcome === "matched") line = "matches the certificate presented";
  else if (b.outcome === "mismatched") line = "does not match: " + b.reason;
  else if (b.outcome === "no-starttls") line = "records published, STARTTLS not offered";
  else if (b.outcome === "no-usable-records") line = "no record a sender uses for SMTP";
  else line = "not established: " + b.reason;
  if (!b.validated) line += " (records not reported validated)";
  return line;
}

// What the MTA-STS row says.
//
// Four states, and the same four the terminal report draws — R16 says one
// result, two renderers, one set of facts, and the only way that holds for a
// sentence built by hand on each side is that somebody writes them together.
// This row said "announced; the policy itself was not fetched" for the whole
// life of the check, which covered a domain fully protected and a domain that
// had been rehearsing for two years, and those are the two readers most need
// told apart.
//
// A mode that was read is shown. A mode that was not is shown as not read, with
// the reason, because an empty mode drawn as a mode is the R4 failure this
// project keeps finding in other tools.
// maxAge writes an MTA-STS max_age in the unit it was most likely chosen in,
// as the terminal's maxAge does (R16).
function maxAge(seconds) {
  const unit = (n, one) => n + " " + one + (n === 1 ? "" : "s");
  if (seconds % 86400 === 0) return unit(seconds / 86400, "day");
  if (seconds % 3600 === 0) return unit(seconds / 3600, "hour");
  return unit(seconds, "second");
}

function stsSays(facts) {
  if (facts.mtaStsReason) {
    return "not read: " + facts.mtaStsReason;
  }
  if (!facts.mtaStsRecords) {
    return "no";
  }
  if (facts.mtaStsPolicyRead && facts.mtaStsMode) {
    let out = "mode " + facts.mtaStsMode;
    // How long a sender keeps the policy, the other half of what it promises.
    if (facts.mtaStsMaxAge > 0) out += ", max_age " + maxAge(facts.mtaStsMaxAge);
    const uncovered = facts.mtaStsUncovered || [];
    if (uncovered.length) {
      const hosts = facts.mxHosts || [];
      out += "; " + uncovered.length + " of the " + hosts.length +
        " exchangers not covered";
    }
    return out;
  }
  if (facts.mtaStsPolicyRead) {
    return "announced; the policy names no mode";
  }
  if (facts.mtaStsPolicyReason) {
    return "announced; the policy was not read: " + facts.mtaStsPolicyReason;
  }
  return "announced; the policy was not read";
}

// ── Submission ──────────────────────────────────────────────────────────

// domainOnly reduces a mail address to its domain, at the last "@".
//
// The part before it is a person, and no check has any use for it. Dropped
// here, in the browser, so it never reaches the service at all — the service
// drops it too, and a promise kept in two places survives either being changed.
function domainOnly(target) {
  const at = target.lastIndexOf("@");
  return at < 0 ? target : target.slice(at + 1);
}

async function check(target, spec, extra) {
  spec = spec || CHECK;
  target = domainOnly(target);
  // Addressed under the check it runs, like the page it is called from.
  //
  // /api/v1/scan is still served and answers identically, because a path in
  // somebody's script is not a link they can be redirected from: a redirect
  // on a POST is followed by some clients and dropped by others, and a body
  // that quietly goes nowhere is worse than a path that stays.
  const response = await fetch(spec.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ target: target }, extra || {})),
    // The hostname is in the body rather than the URL so it stays out of
    // browser history and out of proxy logs. Sending no referrer keeps it out
    // of anything the page links to afterwards.
    referrerPolicy: "no-referrer",
    cache: "no-store",
  });

  // A session that ended while the page was open: the gate says so, and the
  // page goes to sign in rather than reporting a check that never ran.
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Sign in to use this installation.");
  }

  let body = null;
  try {
    body = await response.json();
  } catch {
    throw new Error("The server sent something this page could not read.");
  }

  if (!response.ok) {
    const error = body && body.error ? body.error : {};
    const err = new Error(error.message || "The scan did not complete.");
    err.code = error.code;
    err.status = response.status;
    throw err;
  }

  return body;
}

if (form) form.addEventListener("submit", async event => {
  event.preventDefault();

  const target = input.value.trim();
  if (!target) {
    show(failure("Enter a hostname to check."));
    input.focus();
    return;
  }

  button.disabled = true;
  const label = button.textContent;
  button.textContent = "Checking";

  // A check page draws its one check in the frame every report is read in;
  // the names page draws an inventory, which grades nothing and has its own.
  if (CHECK_ORDER.includes(CHECK_NAME)) {
    try {
      const frame = reportFrame(result, domainOnly(target), [CHECK_NAME], [CHECK_NAME]);
      await reportRun(frame, frame.entries[0], () => check(target, CHECK, asked()));
    } finally {
      button.disabled = false;
      button.textContent = label;
    }
    return;
  }

  show(el("p", "working", CHECK.working));

  try {
    const data = await check(target, CHECK, asked());
    if (CHECK_NAME === "names") namesFrame(result, domainOnly(target), data);
    else show(CHECK.build(data));
  } catch (err) {
    const hint = err.status === 429
      ? "Wait a moment before trying again."
      : err.status === 503
        ? "Several scans are running. Try again shortly."
        : null;
    show(failure(err.message || "The scan did not complete.", hint));
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
});
// ── The report ──────────────────────────────────────────────────────────

// A card's head held at the top of the window is drawn as a bar floating clear
// of the window's edge. Held flush against it, the verdict's coloured edge ran
// into the browser's own bar and read as part of it. Only an observer can tell
// a held head from one at rest, so the class comes from one; without it the
// head is still held, plainly. The 13px is the head's 12px offset and one
// more: a held head sits a pixel above the line, and is then not wholly in.
// Both thresholds, because a jump from far down the page lands a head held
// without its ever having been wholly in view, and a lone threshold of 1 is
// never crossed on the way.
const heldHeads = "IntersectionObserver" in window
  ? new IntersectionObserver((seen) => {
      for (const s of seen) {
        const held = s.rootBounds !== null && s.intersectionRatio < 1 &&
          s.boundingClientRect.top < s.rootBounds.top;
        s.target.classList.toggle("is-held", held);
      }
    }, { rootMargin: "-13px 0px 0px 0px", threshold: [0, 1] })
  : null;

// What one item of a list a builder wrote as "a, b, c" may be. Only a cell
// holding nothing but such items is set as a list (reportLists).
const LIST_ITEM = [
  /^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z0-9-]{2,63}\.?$/i, // a DNS name
  /^\d{1,3}(?:\.\d{1,3}){3}$/,                                          // an IPv4 address
  /^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$/i,                            // an IPv6 address
  /^[a-z0-9_.-]+ \([^()]{1,40}\)$/i,                                    // a selector and its key
];

// reportLists sets a list of names, addresses or keys, which a builder writes
// as one string with commas in it, as one mark per item. Written as a
// sentence, "denyfirst.dev, mta-sts.denyfirst.dev, porch.denyfirst.dev" was
// among the most important answers on the page and looked like the least.
//
// A cell is changed only when its one child is text and every item in it is
// one of LIST_ITEM: a sentence with commas in it, or a cell a builder already
// built, stays as it was. The items are the builder's own text, in its order.
function reportLists(root) {
  for (const cell of root.querySelectorAll("dd, td")) {
    if (cell.childNodes.length !== 1 || cell.firstChild.nodeType !== Node.TEXT_NODE) continue;
    const items = cell.textContent.split(", ");
    if (items.length < 2 || !items.every((item) => LIST_ITEM.some((re) => re.test(item)))) continue;
    clear(cell);
    const list = el("span", "report-list");
    for (const item of items) list.appendChild(el("span", "report-list-item", item));
    cell.appendChild(list);
  }
}

/*
  One frame for every report, whichever page draws it.

  Read in the order a reader asks, and set as a record rather than a
  dashboard. How did it end: the cover, with the domain, one sentence, and a
  board with a row per check, the rule set that graded it, what it found and
  its verdict stamped at the right. What do I have to do: one list of every
  rule any check found broken, the insecure ones first, each stamped with its
  severity and naming the check that found it. And then each check across the
  page: the name it was asked about with its verdict stamped beside it, as the
  first thing in the section, then the evidence at the full width it needs.

  The console, the demonstration, the single-check pages and History all draw
  this, through the same builders from the same JSON (R16), so a report reads
  the same wherever it is opened.

  Nothing on the cover is new evidence. Its figures are counts of findings and
  of what the reports themselves say could not be established, and a check
  that is still running, or did not run, says so in a dashed mark, which no
  verdict is drawn in (R4).
*/
function reportFrame(container, target, names, chosen, opts) {
  opts = opts || {};
  clear(container);
  container.hidden = false;

  const frame = { entries: [], items: [] };
  // The heads of a report drawn before this one are gone with it.
  if (heldHeads) heldHeads.disconnect();

  const cover = el("header", "report-cover");
  frame.cover = cover;
  const lead = el("div", "report-lead");
  lead.appendChild(el("p", "report-eyebrow", "Porch report"));
  lead.appendChild(el("h2", "report-domain", target));
  lead.appendChild(el("p", "report-meta", opts.when
    ? "Kept " + opts.when
    : "Checked " + new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC, " +
      (DEMO_SITE ? "by the demonstration's own server" : "from this installation")));
  const proof = reportProof();
  if (proof && !opts.when) lead.appendChild(el("p", "report-meta", proof));
  cover.appendChild(lead);

  const tally = el("div", "report-tally");
  frame.say = el("p", "report-say", "Running the checks.");
  frame.keys = el("p", "report-keys");
  tally.appendChild(frame.say);
  tally.appendChild(frame.keys);
  cover.appendChild(tally);

  // The board: a row per check, its verdict at the right. A report of one
  // check has its verdict a few lines down, beside the name it is a verdict
  // on, and a board of one row would say it twice.
  const board = el("ol", "report-board");
  board.setAttribute("aria-label", "Checks in this report");
  if (names.length > 1) {
    const wrap = el("div", "report-boardwrap");
    const head = el("div", "report-row report-row-head");
    head.setAttribute("aria-hidden", "true");
    for (const label of ["", "Check", "Graded by", "Found", "Verdict"]) head.appendChild(el("span", null, label));
    wrap.appendChild(head);
    wrap.appendChild(board);
    cover.appendChild(wrap);
  }
  container.appendChild(cover);

  const findings = el("section", "report-findings");
  const heading = el("h2", "report-heading", "Findings");
  frame.found = el("span", "report-heading-count");
  heading.appendChild(frame.found);
  findings.appendChild(heading);
  frame.todo = el("div", "report-todo");
  findings.appendChild(frame.todo);
  container.appendChild(findings);

  // Every check named keeps its row, chosen or not, so the board keeps its
  // shape and says what was left out; one that was not chosen has no section
  // behind it, because there is nothing to show.
  names.forEach((name, i) => {
    const spec = CHECKS[name];
    const on = chosen.includes(name);
    const number = String(i + 1).padStart(2, "0");

    const row = el("li", on ? "report-row" : "report-row report-row-off");
    row.appendChild(el("span", "report-row-num", number));
    const what = el("span", "report-row-name");
    const title = el(on ? "a" : "span", "report-row-title", spec.label);
    what.appendChild(title);
    what.appendChild(el("span", "report-row-says", spec.says));
    row.appendChild(what);
    const policy = el("span", "report-row-policy", "—");
    row.appendChild(policy);
    const count = el("span", "report-row-count", on ? "running" : "not selected");
    row.appendChild(count);
    const state = el("span", "stamp stamp-small stamp-pending", on ? "running" : "off");
    row.appendChild(state);
    board.appendChild(row);
    if (!on) return;
    title.href = "#report-" + name;

    // A card per check. Its head, the check's name and its verdict, stays
    // at the top of the window while the card is read, and gives way to the
    // next card's at the card's end: a reader scrolling through a long
    // report always knows which check the rows in front of them belong to.
    const section = el("section", "report-check report-check-pending");
    section.id = "report-" + name;
    const head = el("header", "report-check-head");
    head.appendChild(el("span", "report-check-num", number));
    const named = el("div", "report-check-named");
    named.appendChild(el("h3", "report-check-name", spec.label));
    named.appendChild(el("p", "report-check-says", spec.says));
    head.appendChild(named);
    const mark = el("span", "stamp stamp-pending", "running");
    head.appendChild(mark);
    section.appendChild(head);
    if (heldHeads) heldHeads.observe(head);
    const top = el("div", "report-check-top");
    section.appendChild(top);
    const body = el("div", "report-body");
    body.appendChild(el("p", "working", spec.working));
    section.appendChild(body);
    container.appendChild(section);

    frame.entries.push({ name, spec, row, state, count, policy, section, mark, top, body, done: false, verdict: null, open: 0 });
  });

  reportTally(frame);
  return frame;
}

// reportFacts sets a list of labelled values as cells, each label over its
// value, so a short value takes a short cell and a long one the whole row.
// Set as one column of label and value, every row of a certificate came out
// the same length, and a reader could not tell its validity from its
// fingerprint without reading both. A row with no label of its own continues
// the one above it, as the logged certificates continue "Logged".
//
// Only the arrangement changes: every node the builder made is kept, in the
// order it made them.
function reportFacts(dl) {
  const cells = [];
  let cell = null;
  for (const node of Array.from(dl.children)) {
    if (node.tagName === "DT" && (node.textContent.trim() !== "" || !cell)) {
      cell = el("div", "report-fact");
      cells.push(cell);
    }
    if (!cell) {
      cell = el("div", "report-fact");
      cells.push(cell);
    }
    cell.appendChild(node);
  }
  clear(dl);
  dl.className = "report-facts";
  for (const c of cells) {
    const values = c.querySelectorAll("dd");
    if (values.length > 1 || c.textContent.length > 46) c.classList.add("report-fact-wide");
    dl.appendChild(c);
  }
}

// reportProof says what this deployment required before it measured the name,
// where it required anything. The page says it because the reader of a report
// handed on cannot see the form it came from.
function reportProof() {
  if (DEMO_SITE) return "Our own domain: the demonstration checks nothing else.";
  if (consoleForm && consoleForm.dataset.proof === "required") {
    return "Measured only after the domain proved, with a record in its zone, that it is yours.";
  }
  return null;
}

// reportRun runs one check into its section, and says so on its row.
//
// A check that could not run says so in its own section and stops nothing:
// a domain with no mail policy, a host that refuses a handshake, a name this
// deployment has not been shown control of are each an answer about one check,
// and letting one end the others would turn a refusal into a blank page.
async function reportRun(frame, entry, run) {
  try {
    reportShow(frame, entry, await run());
  } catch (err) {
    const hint = err.status === 429
      ? "Wait a moment before trying again. Each host has its own budget, whoever asks."
      : err.status === 503
        ? "Several scans are running. Try again shortly."
        : null;
    clear(entry.body);
    entry.body.appendChild(failure(err.message || "The check did not complete.", hint));
    entry.state.textContent = "not run";
    entry.state.className = "stamp stamp-small stamp-pending";
    entry.mark.textContent = "not run";
    entry.count.textContent = "did not run";
    entry.done = true;
    reportTally(frame);
  }
}

// reportShow draws one check's report into its section.
function reportShow(frame, entry, data) {
  const verdict = verdictOf(data);

  // The verdict first, at the head of the card beside the check's name,
  // where it stays in view while the card is read; then the name it is a
  // verdict on and what it rests on; then the evidence.
  const sum = summary(data);
  const stamp = sum.querySelector(".summary-head > .stamp");
  if (stamp) {
    entry.mark.replaceWith(stamp);
    entry.mark = stamp;
  }
  entry.section.className = "report-check " + verdictClass("report-check", verdict);
  clear(entry.top);
  entry.top.appendChild(sum);
  clear(entry.body);
  entry.body.appendChild(entry.spec.build(data));
  for (const dl of entry.body.querySelectorAll("dl.pairs")) reportFacts(dl);
  reportLists(entry.body);

  // The card's foot: where the check is explained, and where it ends. The
  // limits every scan of this kind shares go here too, beside the page that
  // lists them: the same on every report, they are not a finding about this
  // host, and as the last line of the evidence they read as one. What could
  // not be established for this host stays open in the card above (R4).
  const foot = el("div", "report-check-foot");
  foot.appendChild(link(entry.spec.methodPage, "How this check works"));
  const standing = entry.body.querySelector(".notes-method");
  if (standing) foot.appendChild(standing);
  entry.section.appendChild(foot);

  entry.state.textContent = data.verdict ? verdict : "not graded";
  entry.state.className = "stamp stamp-small " + verdictClass("stamp", verdict);
  if (data.policy) entry.policy.textContent = data.policy;

  // A check that reached nothing broke no rule, and saying only that reads
  // as a pass. It is said under the verdict instead: there was nothing to
  // fall short of.
  if (verdict === "ungraded") {
    entry.top.appendChild(el("p", "report-absent",
      "Nothing was measured, so nothing could be graded. This is not a clean result; it is an absent one."));
  }

  const found = Array.isArray(data.findings) ? data.findings : [];
  entry.count.textContent = found.length
    ? (found.length === 1 ? "1 rule broken" : found.length + " rules broken")
    : (data.verdict ? "no rule broken" : "nothing graded");
  for (const f of found) frame.items.push({ f, entry });

  entry.open = (data.notes || []).filter((n) => n && n.kind === "unsettled").length;
  entry.verdict = verdict;
  entry.done = true;
  reportTally(frame);
}

// reportTally writes the cover's sentence and the list of what needs doing,
// from what has arrived so far.
function reportTally(frame) {
  const total = frame.entries.length;
  const done = frame.entries.filter((e) => e.done).length;
  const insecure = frame.items.filter((i) => i.f.verdict === "insecure").length;
  const weak = frame.items.filter((i) => i.f.verdict === "weak").length;
  const open = frame.entries.reduce((n, e) => n + e.open, 0);
  const unrun = frame.entries.filter((e) => e.done && e.verdict === null).length;
  const ungraded = frame.entries.filter((e) => e.verdict === "ungraded").length;

  clear(frame.say);
  if (done < total) {
    frame.say.textContent = "Checking: " + done + " of " + total + " done.";
  } else if (insecure) {
    frame.say.textContent = insecure === 1 ? "1 thing is insecure." : insecure + " things are insecure.";
  } else if (weak) {
    frame.say.textContent = "Nothing is insecure.";
  } else if (unrun || ungraded) {
    // Nothing broken among what was graded is not nothing broken (R4).
    frame.say.textContent = "No rule broken in what could be graded.";
  } else {
    frame.say.textContent = "No rule broken.";
  }

  clear(frame.keys);
  const key = (count, cls, one, many) => {
    const k = el("span", "report-key " + cls);
    k.appendChild(el("b", null, String(count)));
    k.appendChild(document.createTextNode(" " + (count === 1 ? one : many)));
    frame.keys.appendChild(k);
  };
  key(insecure, "report-key-insecure", "insecure", "insecure");
  key(weak, "report-key-weak", "weak", "weak");
  key(open, "report-key-open", "not established", "not established");
  if (unrun) key(unrun, "report-key-open", "check did not run", "checks did not run");

  frame.found.textContent = done < total && !frame.items.length ? "" : String(frame.items.length);

  clear(frame.todo);
  const items = frame.items.slice().sort(
    (a, b) => (VERDICT_ORDER[b.f.verdict] || 0) - (VERDICT_ORDER[a.f.verdict] || 0)
  );
  if (!items.length) {
    frame.todo.appendChild(el("p", "report-todo-empty", done < total
      ? "Nothing yet. The list fills in as each check finishes."
      : (unrun || ungraded)
        ? "None in what was graded. A check that did not run or graded nothing is not a pass."
        : "None. No check found a rule broken."));
    return;
  }
  for (const item of items) frame.todo.appendChild(reportItem(item.f, item.entry));
}

// reportItem is one broken rule, in the list of what needs doing: its
// severity, what the rule says, which check found it and the documents it
// rests on.
function reportItem(f, entry) {
  const item = el("article", "report-item " + verdictClass("report-item", f.verdict));
  item.appendChild(el("span", "stamp stamp-small " + verdictClass("stamp", f.verdict), f.verdict || "finding"));

  const main = el("div", "report-item-main");
  main.appendChild(el("h3", "report-item-title", f.title || "Untitled finding"));
  if (f.rationale) main.appendChild(el("p", "report-item-body", f.rationale));

  const from = el("p", "report-item-from");
  const check = el("a", "report-item-check", entry.spec.label);
  check.href = "#report-" + entry.name;
  from.appendChild(check);
  if (f.ruleId) from.appendChild(el("span", "finding-rule", f.ruleId));
  if (Array.isArray(f.references)) {
    for (const ref of f.references) from.appendChild(link(ref.url, ref.label || ref.url));
  }
  main.appendChild(from);

  item.appendChild(main);
  return item;
}

// ── The names report ────────────────────────────────────────────────────

/*
  The inventory, in the frame a report is drawn in.

  It grades nothing, so the cover carries no verdict and no stamp. It says
  how many names were found, what the ones that were asked about are doing,
  and which source answered with how many — a source that was not asked, or
  could not be read, says that on its row rather than reading as one that
  found nothing (R4).

  One thing does go above the list: a name that is an alias to a name that
  does not exist. Whoever claims that target next answers for the name, which
  is the one finding here that is somebody else's to exploit.
*/
const NAME_SOURCES = [
  ["The zone", "zone"], ["Its proofs", "nsec"], ["Certificates", "logs"], ["Records", "records"],
  ["Passive DNS", "passive"], ["The hosts", "presented"], ["Reverse DNS", "reverse"], ["Your list", "known"],
];

function namesFrame(container, target, data, opts) {
  opts = opts || {};
  clear(container);
  container.hidden = false;
  data = data || {};

  const cover = el("header", "report-cover");
  const lead = el("div", "report-lead");
  lead.appendChild(el("p", "report-eyebrow", "Porch names"));
  lead.appendChild(el("h2", "report-domain", target));
  const kept = data.producedAt && !data.producedAt.startsWith("0001-01-01");
  lead.appendChild(el("p", "report-meta", opts.when
    ? "Kept " + opts.when
    : kept
      ? "Listed " + producedAt(data.producedAt)
      : "Listed " + new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC"));
  const proof = reportProof();
  if (proof && !opts.when) lead.appendChild(el("p", "report-meta", proof));
  cover.appendChild(lead);

  const hosts = (data.names || []).filter((n) => !n.wildcard);
  const status = (n) => (n.now && n.now.status) || "";
  const live = hosts.filter((n) => status(n) === "live").length;
  const elsewhere = hosts.filter((n) => status(n) && status(n) !== "live").length;
  const dangling = hosts.filter((n) => status(n) === "dangling");
  const unclaimed = hosts.filter((n) => status(n) === "unclaimed");
  const distinct = data.distinct || 0;

  const tally = el("div", "report-tally");
  tally.appendChild(el("p", "report-say", distinct === 1 ? "1 name found." : distinct + " names found."));
  const keys = el("p", "report-keys");
  const key = (count, cls, word) => {
    const k = el("span", "report-key " + cls);
    k.appendChild(el("b", null, String(count)));
    k.appendChild(document.createTextNode(" " + word));
    keys.appendChild(k);
  };
  if (data.probed) {
    key(live, "report-key-live", "live");
    key(elsewhere, "report-key-weak", "not live");
  } else {
    keys.appendChild(el("span", "report-key report-key-open", "what each name is doing was not asked"));
  }
  if (data.wildcards) key(data.wildcards, "report-key-open", data.wildcards === 1 ? "wildcard" : "wildcards");
  tally.appendChild(keys);
  cover.appendChild(tally);

  const board = el("ol", "report-board report-board-sources");
  board.setAttribute("aria-label", "Sources read");
  NAME_SOURCES.forEach(([label, field], i) => {
    const reading = data[field] || {};
    const row = el("li", "report-row");
    row.appendChild(el("span", "report-row-num", String(i + 1).padStart(2, "0")));
    row.appendChild(el("span", "report-row-title", label));
    let state;
    if (reading.reason) state = "not established";
    else if (!reading.asked) state = "not asked";
    else state = (reading.named || 0) === 1 ? "1 name" : (reading.named || 0) + " names";
    row.appendChild(el("span", answered(reading) ? "report-row-count" : "report-row-count report-row-quiet", state));
    board.appendChild(row);
  });
  cover.appendChild(board);
  container.appendChild(cover);

  if (dangling.length || unclaimed.length) {
    const findings = el("section", "report-findings");
    const heading = el("h2", "report-heading", "Findings");
    heading.appendChild(el("span", "report-heading-count", String(dangling.length + unclaimed.length)));
    findings.appendChild(heading);
    const todo = el("div", "report-todo");
    const finding = (title, body) => {
      const item = el("article", "report-item report-item-weak");
      item.appendChild(el("span", "stamp stamp-small stamp-weak", "Review"));
      const main = el("div", "report-item-main");
      main.appendChild(el("h3", "report-item-title", title));
      main.appendChild(el("p", "report-item-body", body));
      item.appendChild(main);
      todo.appendChild(item);
    };
    for (const n of dangling) {
      finding(n.name + " is an alias to a name that does not exist",
        "It points at " + n.now.alias + ", which does not resolve. Whoever claims that name next " +
        "answers for " + n.name + ". Remove the alias, or point it at something you control.");
    }
    // What the service said is the measurement; whether it lets somebody
    // else claim the name today is its rule, not something this asked (R17).
    for (const n of unclaimed) {
      finding(n.name + " points at " + n.now.provider + ", which says nobody has claimed it",
        "It is an alias to " + n.now.alias + ", and " + n.now.provider + " answered it as it answers a " +
        "name nobody has claimed there. Whoever claims it there may answer for " + n.name +
        ". Remove the alias, or claim the name again.");
    }
    findings.appendChild(todo);
    container.appendChild(findings);
  }

  const body = el("div", "report-body report-names");
  body.appendChild(buildNames(data));
  for (const dl of body.querySelectorAll("dl.pairs")) reportFacts(dl);
  reportLists(body);
  container.appendChild(body);
}

// ── The console ─────────────────────────────────────────────────────────

/*
  One target, several checks, one report.

  This is the surface a self-hosted installation puts at "/", and it is a
  different thing from the pages at /tls and /web rather than a prettier
  version of them. Those explain a check to somebody who arrived from a log
  line. This runs an estate's checks for the person who runs the estate, and
  the two audiences want opposite things: one wants the argument, the other
  wants the answer and the evidence under it.

  What it is not is a second renderer. Every section here is built by the same
  functions the single-check pages call, from the same JSON, so a sentence
  cannot say one thing on one page and something else on the other — which is
  R16, and which this project has already had to fix twice.

  Sequential rather than parallel, for two reasons. Each check spends a token
  from the scanned host's budget, and three at once from one page is the shape
  the budget exists to discourage. And a section that appears as it finishes is
  a page that is doing something, where three that appear together after nine
  seconds is a page that looks broken.
*/
const consoleForm = document.getElementById("console-form");
const consoleTarget = document.getElementById("console-target");
const consoleButton = document.getElementById("console-submit");
const consoleResults = document.getElementById("console-results");

// selectedChecks reads the boxes, in the order the console draws them.
function selectedChecks() {
  const boxes = document.querySelectorAll("input[name='check']");
  const chosen = new Set();
  boxes.forEach(box => {
    if (box.checked && CHECKS[box.value]) chosen.add(box.value);
  });
  return CHECK_ORDER.filter(name => chosen.has(name));
}

/*
  Proof of control, on an installation that requires it.

  Asked before anything runs, so a name nobody proved anything about gets the
  record to publish rather than three refusals. The dialog stays until the
  record is seen or the person gives up, and the checks run the moment it is
  seen. Nothing here decides anything: the service asks the same question
  again on every scan, and this only saves a round of refusals.
*/
const proofDialog = document.getElementById("proof-dialog");
const VERIFY = { endpoint: "/api/v1/verify" };

function fillProof(records) {
  const level = document.getElementById("proof-level");
  // One choice is not a choice, here as on the Domains page: for
  // example.com there is no domain above it to offer, and a menu holding one
  // item asks a question with one answer (live test 2026-10-20).
  const single = document.getElementById("proof-single");
  const alone = records.length === 1;
  level.hidden = alone;
  single.hidden = !alone;
  if (alone) single.textContent = records[0].domain;
  clear(level);
  records.forEach((r, i) => {
    const option = el("option", null, r.domain);
    option.value = String(i);
    level.appendChild(option);
  });
  const pick = () => {
    const r = records[Number(level.value)] || records[0];
    document.getElementById("proof-name").textContent = r.name;
    document.getElementById("proof-value").textContent = r.value;
  };
  level.onchange = pick;
  // The name itself by default, which is the first in the list. A domain
  // above it is the operator's choice to make, never this page's: the last
  // entry for www.shop.co.uk is co.uk, a zone nobody who owns shop.co.uk
  // controls, and a record there would speak for every name under it (audit
  // 2026-09-18, D05). The service cannot tell a public suffix from a
  // registrable domain, so it does not guess.
  level.value = "0";
  pick();
}

// waitForProof resolves true once the record is seen, false if abandoned.
function waitForProof(target, first) {
  const status = document.getElementById("proof-status");
  const again = document.getElementById("proof-check");
  const cancel = document.getElementById("proof-cancel");

  fillProof(first.records || []);
  status.textContent = "";
  proofDialog.showModal();

  return new Promise(resolve => {
    const finish = ok => {
      again.onclick = null;
      cancel.onclick = null;
      proofDialog.oncancel = null;
      if (proofDialog.open) proofDialog.close();
      resolve(ok);
    };

    cancel.onclick = () => finish(false);
    proofDialog.oncancel = () => finish(false);

    again.onclick = async () => {
      again.disabled = true;
      status.textContent = "Looking for the record…";
      try {
        const answer = await check(target, VERIFY);
        if (answer.verified) {
          status.textContent = "Found. Running the checks.";
          finish(true);
          return;
        }
        status.textContent = "Not there yet. DNS can take a few minutes; check again shortly.";
      } catch (err) {
        status.textContent = err.status === 429
          ? "Asked too often. Wait a few seconds and check again."
          : (err.message || "The record could not be looked up.");
      } finally {
        again.disabled = false;
      }
    };
  });
}

/*
  Copying a proof record or an install command, and nothing else.

  The one place this script writes to the clipboard. A report is never put
  there: it names a host and what was found on it, and the clipboard is shared
  with every process on the machine and sometimes synced off it. A proof record
  is the opposite case. It exists to be pasted into a DNS provider's form, it
  proves nothing until it is published in that domain's zone, and the person
  pressing the button is about to paste it. Where the browser refuses the
  write, the text is selected instead, so one keystroke still copies it.

  The commands on the Porch page are the same case, and more so: fixed text,
  the same for every visitor, naming no host anybody asked about. What is
  copied is the text of the element on the screen, never a second string kept
  beside it — a page that copies something other than what it shows is how a
  command pasted into a terminal runs something its reader never saw.

  The update commands on New check are that case too: text written in this
  file, and a version number that came from a list the release key signed
  and that is used only once it reads as a release name (updateCommands).
  They name no host and nothing found; a version is public.
*/
async function copyRecord(button) {
  const source = document.getElementById(button.dataset.copy);
  if (!source) return;
  const text = source.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch {
    const range = document.createRange();
    range.selectNodeContents(source);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    button.textContent = "Selected";
  }
  setTimeout(() => { button.textContent = "Copy"; }, 1500);
}

for (const holder of [proofDialog, document.getElementById("domain-record"), document.querySelector("#start .steps"), document.getElementById("update-banner")]) {
  if (!holder) continue;
  holder.addEventListener("click", event => {
    const button = event.target.closest("[data-copy]");
    if (button) copyRecord(button);
  });
}

/*
  Domains: the record for one domain, asked for before a check needs it.

  The same question the console asks when a check meets a new domain, through
  the same endpoint, shown on the page instead of in a dialog.
*/
const domainForm = document.getElementById("domain-form");
const domainRecord = document.getElementById("domain-record");

function showDomainRecord(answer) {
  const state = document.getElementById("domain-state");
  const level = document.getElementById("domain-level");
  const records = answer.records || [];

  // Signed is the resolver's word that it checked DNSSEC, and is shown as
  // that: not this page's work, and worth what the resolver is worth (A06).
  //
  // Unsigned said the proof rested on the resolver's answer alone. Since the
  // record is read from the zone's own servers it rests on no resolver, and
  // signed is false wherever the question was not asked, so the sentence was
  // wrong twice. It says what was not asked instead (R17).
  state.textContent = answer.verified
    ? "Proven. Every check may run against this domain. " + (answer.signed
      ? "The resolver reported the record DNSSEC-signed."
      : "Whether the record is DNSSEC-signed was not asked: -verification-requires-dnssec asks.")
    : "Not proven yet. Publish this record, then check again.";
  state.className = "domain-state " + (answer.verified ? "mark-strong" : "mark-weak");

  // Nothing to publish is nothing to show. A name that was refused, or an
  // answer carrying no record, used to leave this block standing with an empty
  // chooser and two Copy buttons for nothing.
  const proof = document.getElementById("domain-proof");
  proof.hidden = records.length === 0;
  if (records.length === 0) return;

  // One choice is not a choice. The chooser exists because a record on a domain
  // above covers everything beneath it, and above example.com there is nothing
  // to offer — a dropdown holding one item asks a question with one answer.
  const single = document.getElementById("domain-single");
  const only = records.length === 1;
  level.hidden = only;
  single.hidden = !only;
  if (only) single.textContent = records[0].domain;

  clear(level);
  records.forEach((r, i) => {
    const option = el("option", null, r.domain);
    option.value = String(i);
    level.appendChild(option);
  });
  const pick = () => {
    const r = records[Number(level.value)] || records[0];
    if (!r) return;
    document.getElementById("domain-name").textContent = r.name;
    document.getElementById("domain-value").textContent = r.value;
  };
  level.onchange = pick;
  // The name itself by default, as the console's dialog does, and for the
  // same reason.
  level.value = "0";
  pick();
  domainRecord.hidden = false;
}

if (domainForm && domainRecord) {
  const target = document.getElementById("domain-target");
  const submit = document.getElementById("domain-submit");
  const again = document.getElementById("domain-again");

  const ask = async (button) => {
    const name = target.value.trim();
    const state = document.getElementById("domain-state");
    if (!name) {
      target.focus();
      return;
    }
    button.disabled = true;
    try {
      showDomainRecord(await check(name, VERIFY));
    } catch (err) {
      domainRecord.hidden = false;
      // The message and nothing else: there is no record for a name that was
      // refused, and the block below used to stay behind holding empty fields.
      document.getElementById("domain-proof").hidden = true;
      state.className = "domain-state mark-weak";
      state.textContent = err.status === 429
        ? "Asked too often. Wait a few seconds and try again."
        : (err.message || "The record could not be looked up.");
    } finally {
      button.disabled = false;
    }
  };

  domainForm.addEventListener("submit", async event => {
    event.preventDefault();
    // Behind a password, an added domain is kept on the list as well as
    // shown its record.
    if (domainTable && target.value.trim()) {
      try {
        await domainRequest("POST", "/api/v1/domains", { domain: target.value.trim() });
      } catch (err) {
        domainListStatus(err.message);
        return;
      }
      loadDomains();
    }
    ask(submit);
  });
  again.addEventListener("click", async () => {
    await ask(again);
    if (domainTable) loadDomains();
  });
}

/*
  The domain list, on an installation behind a password.

  Names and dates come from the sealed list; whether each is proven is asked
  of DNS now, one domain after another, through the same endpoint the console
  asks. That endpoint shares the scan budget, so a long list is asked until
  the budget says wait, and the rest offer a button to ask when it has
  refilled rather than reading as unproven.
*/
const domainTable = document.getElementById("domain-table");

async function domainRequest(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Sign in to use this installation.");
  }
  if (response.status === 204 || response.status === 201 || (response.ok && method !== "GET")) return null;
  let data = null;
  try {
    data = await response.json();
  } catch {
    throw new Error("The installation sent something this page could not read.");
  }
  if (!response.ok) {
    const error = data && data.error ? data.error : {};
    throw new Error(error.message || "The domain list could not be read.");
  }
  return data;
}

function domainListStatus(text) {
  const status = document.getElementById("domain-list-status");
  status.textContent = text;
  status.hidden = !text;
}

async function proveRow(domain, cell) {
  clear(cell);
  cell.className = "mark-faint";
  cell.textContent = "asking…";
  try {
    const answer = await check(domain.name, VERIFY);
    cell.className = answer.verified ? "mark-strong" : "mark-weak";
    cell.textContent = answer.verified ? (answer.signed ? "proven, signed" : "proven") : "not proven";
    return true;
  } catch (err) {
    cell.className = "mark-faint";
    cell.textContent = err.status === 429 ? "not asked yet " : "not established ";
    const retry = el("button", "history-open", "Ask");
    retry.type = "button";
    retry.addEventListener("click", () => proveRow(domain, cell));
    cell.appendChild(retry);
    return err.status !== 429;
  }
}

function domainRow(domain) {
  const row = el("tr");
  row.appendChild(el("td", "history-target", domain.name));
  row.appendChild(el("td", null, domain.added));
  const proof = el("td", "mark-faint", "…");
  row.appendChild(proof);

  const actions = el("td", "history-actions");
  const record = el("button", "history-open", "Record");
  record.type = "button";
  const remove = el("button", "history-delete", "Remove");
  remove.type = "button";
  actions.appendChild(record);
  actions.appendChild(remove);
  row.appendChild(actions);

  record.addEventListener("click", () => {
    document.getElementById("domain-target").value = domain.name;
    document.getElementById("domain-again").click();
    domainRecord.scrollIntoView({ block: "start" });
  });
  remove.addEventListener("click", async () => {
    if (!window.confirm("Take " + domain.name + " off the list? Its record in DNS and its " +
        "reports in History stay where they are.")) return;
    remove.disabled = true;
    try {
      await domainRequest("DELETE", "/api/v1/domains/" + encodeURIComponent(domain.name));
      loadDomains();
    } catch (err) {
      domainListStatus(err.message);
      remove.disabled = false;
    }
  });
  return { row, proof, domain };
}

async function loadDomains() {
  let data;
  try {
    data = await domainRequest("GET", "/api/v1/domains");
  } catch (err) {
    domainListStatus(err.message);
    return;
  }
  domainListStatus("");
  const list = (data && data.domains) || [];
  const rows = document.getElementById("domain-rows");
  clear(rows);
  const made = list.map(domainRow);
  for (const m of made) rows.appendChild(m.row);
  domainTable.hidden = list.length === 0;
  document.getElementById("domain-list-empty").hidden = list.length !== 0;

  // One at a time, and stop asking once the budget says wait.
  for (const m of made) {
    if (!(await proveRow(m.domain, m.proof))) {
      for (const rest of made.slice(made.indexOf(m) + 1)) {
        clear(rest.proof);
        rest.proof.textContent = "not asked yet ";
        const ask = el("button", "history-open", "Ask");
        ask.type = "button";
        ask.addEventListener("click", () => proveRow(rest.domain, rest.proof));
        rest.proof.appendChild(ask);
      }
      break;
    }
  }
}

if (domainTable) loadDomains();

// proven says whether the checks may run, asking for proof first where it is
// required. A failure to ask is shown in the results and ends the run.
async function proven(target) {
  if (!consoleForm || consoleForm.dataset.proof !== "required" || !proofDialog) return true;

  let answer;
  try {
    answer = await check(target, VERIFY);
  } catch (err) {
    consoleResults.appendChild(failure(err.message || "Whether this name is proven could not be checked."));
    return false;
  }
  if (!answer.required || answer.verified) return true;
  return waitForProof(target, answer);
}

if (consoleForm) {
  consoleForm.addEventListener("submit", async event => {
    event.preventDefault();

    const target = consoleTarget.value.trim();
    if (!target) {
      clear(consoleResults);
      consoleResults.hidden = false;
      consoleResults.appendChild(failure("Enter a hostname to check."));
      consoleTarget.focus();
      return;
    }

    const chosen = selectedChecks();
    if (chosen.length === 0) {
      clear(consoleResults);
      consoleResults.hidden = false;
      consoleResults.appendChild(failure("Choose at least one check."));
      return;
    }

    consoleButton.disabled = true;
    const label = consoleButton.textContent;
    consoleButton.textContent = "Checking";

    clear(consoleResults);
    consoleResults.hidden = false;

    try {
      if (!(await proven(target))) return;

      // Awaited one at a time on purpose. See the note above.
      const frame = reportFrame(consoleResults, target, CHECK_ORDER, chosen);
      for (const entry of frame.entries) {
        await reportRun(frame, entry, () => check(target, entry.spec, selectorsAsked(entry.name)));
      }
    } finally {
      consoleButton.disabled = false;
      consoleButton.textContent = label;
    }
  });
}

// ── The Porch page ──────────────────────────────────────────────────────

/*
  Every check on one name, in the frame every report is drawn in.

  It was a tab per check. The board's rows on the cover now do what the tabs
  did — each carries its own state, running, a verdict, not graded or not
  run, so a TLS result is never read as saying anything about mail — and
  what the tabs could not do is the list above the checks: every rule any of
  them found broken, in one place, worst first.
*/
const porchForm = document.getElementById("porch-form");
const porchTarget = document.getElementById("porch-target");
const porchButton = document.getElementById("porch-submit");
const porchResults = document.getElementById("porch-results");

if (porchForm) {
  porchForm.addEventListener("submit", async event => {
    event.preventDefault();

    const target = porchTarget.value.trim();
    const chosen = selectedChecks();
    if (!target || chosen.length === 0) {
      clear(porchResults);
      porchResults.hidden = false;
      porchResults.appendChild(failure(target ? "Choose at least one check." : "Choose a domain to check."));
      return;
    }

    porchButton.disabled = true;
    const label = porchButton.textContent;
    porchButton.textContent = "Checking";

    try {
      const frame = reportFrame(porchResults, target, CHECK_ORDER, chosen);
      const still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      porchResults.scrollIntoView({ behavior: still ? "auto" : "smooth", block: "start" });

      // One at a time, as the console runs them: each check spends from the
      // host's budget, and three at once is the shape the budget discourages.
      for (const entry of frame.entries) {
        await reportRun(frame, entry, () => check(target, entry.spec));
      }
    } finally {
      porchButton.disabled = false;
      porchButton.textContent = label;
    }
  });
}

/*
  History, on an installation behind a password.

  The list is asked for once the page has loaded, through the gate; nothing
  of it is in the page itself. Each row opens its report with the same
  builders New check draws with (R16), from the JSON that was kept, so a
  report reopened is the report that was drawn. Delete asks first, then
  removes the report for good.
*/
const historyBox = document.getElementById("history");
const historyReport = document.getElementById("history-report");

// The list as it was last drawn, so that a report opened from it can find the
// one kept before it for the same check and host.
let historyEntries = [];

/*
  What changed between a report and the one kept before it, for the same
  check against the same host.

  Findings are matched by rule identifier and title. The identifier is stable
  across releases (policy.Finding says so), so a finding that appears or goes
  away is named by the rule that produced it, and nothing is inferred from
  prose.

  A verdict is set beside the earlier one only where both were graded under
  the same rule set. A verdict from one means nothing under another, and two
  side by side would say otherwise.

  And where either report measured nothing, no finding is listed at all:
  nothing measured is not the same as passing (R4), so a finding missing from
  a report that measured nothing has not gone away — it was not looked for.
*/
function reportFindings(report) {
  const found = new Map();
  const walk = (node, depth) => {
    if (depth > 16 || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (typeof node.ruleId === "string" && typeof node.title === "string") {
      const key = node.ruleId + "\u0000" + node.title;
      if (!found.has(key)) found.set(key, { ruleId: node.ruleId, title: node.title });
      return;
    }
    for (const value of Object.values(node)) walk(value, depth + 1);
  };
  walk(report, 0);
  return found;
}

function reportChanges(now, before) {
  const graded = r => r && VERDICTS.includes(r.verdict);
  const changes = {
    samePolicy: typeof now.policy === "string" && now.policy !== "" && now.policy === before.policy,
    measured: graded(now) && graded(before),
    verdictNow: graded(now) ? now.verdict : "not graded",
    verdictBefore: graded(before) ? before.verdict : "not graded",
    appeared: [],
    gone: [],
  };
  if (!changes.measured) return changes;
  const a = reportFindings(now);
  const b = reportFindings(before);
  for (const [key, finding] of a) if (!b.has(key)) changes.appeared.push(finding);
  for (const [key, finding] of b) if (!a.has(key)) changes.gone.push(finding);
  return changes;
}

function changesBlock(changes, now, before, beforeDate) {
  const box = el("section", "history-changes");
  box.appendChild(el("h3", null, "Since the report kept " + beforeDate));

  if (changes.samePolicy) {
    const verdict = el("p");
    verdict.appendChild(document.createTextNode("Verdict: "));
    if (changes.verdictNow === changes.verdictBefore) {
      verdict.appendChild(el("span", markClass(changes.verdictNow), changes.verdictNow));
      verdict.appendChild(document.createTextNode(" then and now."));
    } else {
      verdict.appendChild(el("span", markClass(changes.verdictBefore), changes.verdictBefore));
      verdict.appendChild(document.createTextNode(" then, "));
      verdict.appendChild(el("span", markClass(changes.verdictNow), changes.verdictNow));
      verdict.appendChild(document.createTextNode(" now."));
    }
    box.appendChild(verdict);
  } else {
    box.appendChild(el("p", null, "Graded under " + (before.policy || "no rule set") + " then and " +
      (now.policy || "no rule set") + " now. A verdict from one rule set means nothing under " +
      "another, so the two verdicts are not compared."));
  }

  if (!changes.measured) {
    box.appendChild(el("p", null, "One of the two reports measured nothing that could be graded, " +
      "so no finding is compared: a finding missing from it was not looked for, which is not " +
      "the same as gone."));
    return box;
  }

  const list = (title, findings) => {
    if (!findings.length) return;
    box.appendChild(el("p", "history-changes-title", title));
    const ul = el("ul");
    for (const f of findings) {
      const li = el("li", null, f.title + " ");
      li.appendChild(el("code", null, f.ruleId));
      ul.appendChild(li);
    }
    box.appendChild(ul);
  };
  list("In this report and not in the earlier one:", changes.appeared);
  list("In the earlier report and not in this one:", changes.gone);
  if (!changes.appeared.length && !changes.gone.length) {
    box.appendChild(el("p", null, "The same findings, by rule, in both."));
  }
  return box;
}

// earlierEntry is the report kept before this one for the same check and
// host, or null. Seq orders reports kept on the same date.
function earlierEntry(entry) {
  let best = null;
  for (const other of historyEntries) {
    if (other.id === entry.id || other.check !== entry.check || other.target !== entry.target) continue;
    const earlier = other.date < entry.date || (other.date === entry.date && other.seq < entry.seq);
    if (!earlier) continue;
    if (!best || other.date > best.date || (other.date === best.date && other.seq > best.seq)) best = other;
  }
  return best;
}

async function historyRequest(method, path) {
  const response = await fetch(path, { method, credentials: "same-origin", cache: "no-store" });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Sign in to use this installation.");
  }
  if (response.status === 204) return null;
  let body = null;
  try {
    body = await response.json();
  } catch {
    throw new Error("The installation sent something this page could not read.");
  }
  if (!response.ok) {
    const error = body && body.error ? body.error : {};
    throw new Error(error.message || "The history could not be read.");
  }
  return body;
}

function historyRow(entry) {
  const spec = CHECKS[entry.check];
  const row = el("tr");
  row.appendChild(el("td", null, entry.date));
  row.appendChild(el("td", "history-target", entry.target));
  row.appendChild(el("td", null, spec ? spec.label : entry.check));
  const verdict = VERDICTS.includes(entry.verdict) ? entry.verdict : "not graded";
  row.appendChild(el("td", markClass(entry.verdict), verdict));

  const actions = el("td", "history-actions");
  const open = el("button", "history-open", "Open");
  open.type = "button";
  const remove = el("button", "history-delete", "Delete");
  remove.type = "button";
  actions.appendChild(open);
  actions.appendChild(remove);
  row.appendChild(actions);

  open.addEventListener("click", async () => {
    open.disabled = true;
    try {
      const record = await historyRequest("GET", "/api/v1/history/" + entry.id);
      const view = CHECK_ORDER.includes(record.check) ? CHECKS[record.check] : null;
      clear(historyReport);
      // In the frame every report is drawn in, with one check, saying when
      // it was kept rather than when it was checked.
      let frame = null;
      if (view) {
        frame = reportFrame(historyReport, entry.target, [record.check], [record.check], { when: record.date });
        reportShow(frame, frame.entries[0], record.report);
      }
      // The report kept before this one for the same check and host, set
      // under the cover. Asked for only when this one is opened, through the
      // same gate; a failure to read it costs the comparison and nothing else.
      const previous = earlierEntry(entry);
      if (frame && previous && previous.policy && record.report && typeof record.report === "object" &&
          typeof record.report.policy === "string" && record.report.policy !== "") {
        try {
          const before = await historyRequest("GET", "/api/v1/history/" + previous.id);
          if (before && before.report && typeof before.report === "object") {
            const changes = reportChanges(record.report, before.report);
            frame.cover.after(changesBlock(changes, record.report, before.report, previous.date));
          }
        } catch {
          // The comparison is extra; the report below is what was asked for.
        }
      }
      if (!view && record.check === "names") {
        // An inventory grades nothing and is drawn as one.
        namesFrame(historyReport, entry.target, record.report, { when: record.date });
      } else if (!view) {
        historyReport.appendChild(failure("This report is from a check this build does not draw."));
      }
      historyReport.hidden = false;
      historyReport.scrollIntoView({ block: "start" });
    } catch (err) {
      historyStatus(err.message);
    } finally {
      open.disabled = false;
    }
  });

  remove.addEventListener("click", async () => {
    if (!window.confirm("Delete the " + (spec ? spec.label : entry.check) + " report for " +
        entry.target + " from " + entry.date + "? It cannot be brought back.")) return;
    remove.disabled = true;
    try {
      await historyRequest("DELETE", "/api/v1/history/" + entry.id);
      historyEntries = historyEntries.filter(other => other.id !== entry.id);
      row.remove();
      clear(historyReport);
      historyReport.hidden = true;
      if (!document.getElementById("history-rows").children.length) showHistory([]);
      historyStatus("Deleted.");
    } catch (err) {
      historyStatus(err.message);
      remove.disabled = false;
    }
  });
  return row;
}

function historyStatus(text) {
  const status = document.getElementById("history-status");
  status.textContent = text;
  status.hidden = !text;
}

function showHistory(entries) {
  const table = document.getElementById("history-table");
  const rows = document.getElementById("history-rows");
  clear(rows);
  historyEntries = entries.filter(entry => entry && typeof entry.id === "string");
  for (const entry of entries) rows.appendChild(historyRow(entry));
  table.hidden = entries.length === 0;
  document.getElementById("history-empty").hidden = entries.length !== 0;
}

// What the history holds besides the list: files this password does not open,
// which the bound never removes, and reports it could not remove. Said, so
// that "at most a thousand" is never read as a promise about the disk.
function historyNote(status) {
  const note = document.getElementById("history-note");
  if (!note) return;
  const parts = [];
  if (status && status.unreadable > 0) {
    const size = status.unreadableBytes >= 1048576
      ? (status.unreadableBytes / 1048576).toFixed(1) + " MB"
      : Math.max(1, Math.round(status.unreadableBytes / 1024)) + " kB";
    const one = status.unreadable === 1;
    parts.push(status.unreadable + (one ? " file" : " files") + " in the history (" + size + ")" +
      (one ? " does" : " do") + " not open with this password. Kept under another one, or " +
      "damaged, " + (one ? "it is" : "they are") + " left for whoever runs the server to decide about.");
  }
  if (status && status.overBound > 0) {
    const one = status.overBound === 1;
    parts.push(status.overBound + (one ? " report" : " reports") + " past the bound could not " +
      "be removed. The next check tries again.");
  }
  note.textContent = parts.join(" ");
  note.hidden = parts.length === 0;
}

if (historyBox && historyReport) {
  historyRequest("GET", "/api/v1/history")
    .then(body => {
      historyStatus("");
      showHistory((body && body.entries) || []);
      historyNote(body && body.status);
    })
    .catch(err => historyStatus(err.message));
}

// daneSummary says how many exchangers publish DANE records, or why the
// question could not be put, in the words the terminal uses (R16).
//
// The count and the four ways there is no count, in one place, because the row
// is drawn whether or not there is an answer and each kind of nothing sends a
// reader somewhere different: a domain that accepts no mail has nothing to
// protect, one whose exchangers could not be read has an unknown answer, and
// one whose exchangers publish no records has a measured one.
function daneSummary(facts) {
  const hosts = facts.mxHosts || [];
  const dane = facts.daneHosts || [];

  if (facts.nullMX) return "not checked: the domain accepts no mail";
  if (facts.mxReason || !facts.mxRead) return "not checked: the exchangers are not known";
  if (hosts.length === 0) return "not checked: the domain publishes no exchanger";
  if (hosts.length === 1 && dane.length === 0) return "none at the one exchanger";
  if (hosts.length === 1) return "at the one exchanger";
  if (dane.length === 0) return "none at the " + hosts.length + " exchangers";
  if (dane.length === hosts.length) return "at all " + hosts.length + " exchangers";
  return "at " + dane.length + " of the " + hosts.length + " exchangers: " + dane.join(", ");
}

// ── The name inventory ──────────────────────────────────────────────────
//
// Not a check and drawn as one thing rather than as a graded report: there is
// no verdict, no findings list and no rule set, because no document says which
// names an estate ought to have. What there is, is a list, the window each name
// was covered in, and — under every one of them — the paragraph saying what the
// list is missing.
//
// That paragraph is not a footnote to be collapsed. A list of forty names read
// without it says "this estate has forty hosts", which is not what a
// certificate log establishes for anybody.
// readings is every source the service sends, in the order the report prints
// them, and it is the only place that list lives.
//
// internal/inventory.Inventory.Readings is its other half, for the same
// reason: three separate places had each decided for themselves how many
// sources there are, and every one of them was short by the time the sixth
// arrived.
function readings(data) {
  return [data.zone, data.nsec, data.logs, data.records, data.passive, data.presented,
          data.reverse, data.known]
    .map((r) => r || {});
}

function buildNames(data) {
  const frag = document.createDocumentFragment();
  if (!data) return frag;

  frag.appendChild(sectionTitle("Names under this domain"));

  if (!readings(data).some(answered)) {
    // Not one source answered, so there is no inventory. The reassuring
    // answer here is "none found", so a failure that rendered as an empty
    // list would be the most comfortable wrong answer available.
    //
    // Both halves of this read a list of five and a list of three while six
    // sources could fail. An installation whose only answering source was the
    // reverse walk was told nothing had been established; one whose only
    // configured source was the zone was told that and then given no reason
    // for it. A page that says a thing could not be established and will not
    // say what or why is worse than the empty list this was written to avoid
    // (R4, I6). There is one list now, and it is the list every other part of
    // this report reads.
    for (const reading of readings(data)) {
      const reason = reading && reading.reason;
      if (reason) frag.appendChild(el("p", null, "Not established: " + reason));
    }
    return frag;
  }

  const counts = el("table", "grid");
  const body = el("tbody");
  const row = (name, value) => {
    const tr = el("tr");
    tr.appendChild(el("th", null, name));
    tr.appendChild(el("td", null, value));
    body.appendChild(tr);
  };

  const distinct = data.distinct || 0;
  row("Found", distinct + (distinct === 1 ? " distinct name" : " distinct names"));

  // A kept copy says when it was made. Without it the freshest thing here —
  // what each name is doing — reads as current whatever its age, which is the
  // one claim this whole mode exists to get right.
  if (data.producedAt && !data.producedAt.startsWith("0001-01-01")) {
    row("Produced", producedAt(data.producedAt));
  }

  // Then one line per source, always, including the one that failed. Six
  // names from two sources and six names from one that answered while the
  // other timed out are the same six names, and only these two lines tell a
  // reader which report they are holding.
  row("The zone", saysZone(data));
  row("Its proofs", saysNsec(data));
  row("Certificates", saysLogs(data));
  row("Records", saysRecords(data));
  row("Passive DNS", saysPassive(data));
  row("The hosts", saysPresented(data));
  row("Reverse DNS", saysReverse(data));
  row("Your list", saysKnown(data));

  if (data.wildcards) {
    row("Wildcards", data.wildcards + ", each covering hosts it does not name");
  }
  const other = otherNames((data.logs || {}).foreign || 0, (data.records || {}).foreign || 0);
  if (other) row("Other names", other);
  if (data.truncated) {
    row("Cut", "more names were found than are listed");
  }
  counts.appendChild(body);
  frag.appendChild(counts);

  const names = data.names || [];
  const hosts = names.filter((n) => !n.wildcard);
  if (hosts.length) {
    // Three columns rather than two, because what named a host decides what a
    // reader does about it: one only a log has is a host somebody obtained a
    // certificate for, one only the records have is a host the domain
    // publishes itself, and one both have is the well-kept case that needs
    // nobody's time.
    const table = el("table", "rows");
    const head = el("tr");
    const labels = data.probed
      ? ["Name", "Named by", "Doing now", "In the logs"]
      : ["Name", "Named by", "In the logs"];
    for (const label of labels) {
      head.appendChild(el("th", null, label));
    }
    table.appendChild(el("thead")).appendChild(head);

    const rows = el("tbody");
    for (const name of hosts) {
      const tr = el("tr");

      // hostname rather than identifier: a name is a word somebody reads and
      // then goes and looks at, so it is not broken mid-word where there is
      // room for it. The class is in style.css with the trade written out.
      tr.appendChild(el("td", "hostname", name.name));
      tr.appendChild(el("td", null, namedBy(name)));

      // Every name in the inventory gets a row, whether or not an answer came
      // back for it. Drawing the rows from the answers instead is how a name
      // leaves a report without being mentioned: the probe bounds how many
      // names it reaches and gives up on the rest when the time runs out.
      if (data.probed) tr.appendChild(doingCell(name));

      tr.appendChild(el("td", loggedWindow(name) ? null : "mark-faint", covered(name, data)));
      rows.appendChild(tr);
    }
    table.appendChild(rows);
    frag.appendChild(table);
  }

  // A wildcard is listed apart and without a source column: nothing but a
  // certificate names one, and what it is doing is hiding however many hosts
  // are behind it.
  const wildcards = names.filter((n) => n.wildcard);
  if (wildcards.length) {
    frag.appendChild(sectionTitle("Wildcards, which name no host"));
    const table = el("table", "rows");

    // Headed, like the table above it. Two unlabelled columns of dates and
    // names left a reader to work out which was which, and the second one is
    // a sentence about certificates that reads as a note until it is under a
    // heading saying it is the same column as the one above.
    const head = el("tr");
    for (const label of ["Wildcard", "In the logs"]) {
      head.appendChild(el("th", null, label));
    }
    table.appendChild(el("thead")).appendChild(head);

    const rows = el("tbody");
    for (const name of wildcards) {
      const tr = el("tr");
      tr.appendChild(el("td", "hostname", name.name));
      tr.appendChild(el("td", null, covered(name, data)));
      rows.appendChild(tr);
    }
    table.appendChild(rows);
    frag.appendChild(table);
  }

  frag.appendChild(namesLimits(data));
  return frag;
}

// producedAt says how old a kept inventory is, in the words somebody reads
// rather than as a timestamp they have to subtract from now.
//
// The exact time as well, because "an hour ago" is a rounding and the reader
// deciding whether to act on a dead name wants the real one.
function producedAt(when) {
  const at = new Date(when);
  if (isNaN(at.getTime())) return "earlier";

  const minutes = Math.floor((Date.now() - at.getTime()) / 60000);
  const ago =
    minutes < 1 ? "just now" :
    minutes === 1 ? "a minute ago" :
    minutes < 60 ? minutes + " minutes ago" :
    minutes < 120 ? "an hour ago" :
    Math.floor(minutes / 60) + " hours ago";

  return ago + ", at " + at.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

// answered reports that one source was read and said something.
//
// Read and silent is an answer; unread is not, and neither is a monitor that
// could not be reached. The three render differently for that reason.
function answered(reading) {
  return Boolean(reading && reading.asked) && !reading.reason;
}

// saysNsec is what the zone's own absence proofs listed.
//
// Usually nothing, and that is the source rather than a fault in it: a zone
// using NSEC3, or not signed at all, publishes no plain chain to follow. Where
// there is one it lists the zone, out of records the zone serves to any
// resolver — which is the thing the DNS check reports and, until this, could
// not show.
function saysNsec(data) {
  const r = data.nsec || {};

  if (!r.asked) return "not walked: this installation does not follow them";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named) return "named none of them";
  return "named " + r.named + " of them, out of the zone's own absence proofs";
}

// saysZone is what the zone handed over, in one line.

//
// A refusal is a first-class answer here rather than a failure: a zone is
// handed to the secondaries its operator named and to nobody else, so "every
// server refused" is somebody reading their own DNS working as it should.
function saysZone(data) {
  const r = data.zone || {};

  if (!r.asked) return "not asked: this installation does not ask for one";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named && r.transferred) return "named none of them: the zone was handed over and holds no other name under it";
  if (!r.named) return "named none of them: every server refused the transfer, which is the ordinary answer";
  return "named " + r.named + " of them, handed over by the zone itself";
}

// saysLogs is what the certificate monitor established, in one line.
function saysLogs(data) {
  const r = data.logs || {};
  const certificates = data.certificates || 0;
  const over = certificates + (certificates === 1 ? " certificate" : " certificates");

  if (!r.asked) return "not read";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named && !certificates) {
    return "named none of them: no publicly logged certificate covers a host here";
  }
  if (!r.named) return "named none of them, in " + over + " read";
  return "named " + r.named + " of them, across " + over;
}

// saysRecords is what the domain's own records established, in one line.
//
// It names the record types that carried a name rather than the three that
// were read, because the difference is the finding: a domain whose names all
// came from its delegation publishes no mail and no sender policy.
function saysRecords(data) {
  const r = data.records || {};

  if (!r.asked) return "not read";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named && r.unread) return "named none of them in what was read; not read: " + r.unread;
  if (!r.named) {
    return "named none of them: its mail, sender policy and delegation name no host under it";
  }
  return "named " + r.named + " of them, from " + wordList(recordSources(data)) + notRead(r);
}

// notRead is what a source could not read, where it read the rest, as the
// tail of its line, as on the command line.
function notRead(r) {
  return r.unread ? "; not read: " + r.unread : "";
}

// saysPassive is what a passive register observed, in one line.
//
// "Not read" where none was configured, because that is the ordinary state and
// a reader has to be able to tell it from a register that answered with
// nothing. This is the source that sees behind a wildcard: an estate covered
// by one, read with this line saying "not read", is a reader being told
// exactly how much they are not seeing.
function saysPassive(data) {
  const r = data.passive || {};

  if (!r.asked) return "not read: no register was named";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named) return "named none of them: the register has observed no host under this domain";
  return "named " + r.named + " of them, observed by the register";
}

// saysKnown is what the list somebody already had contributed.
//
// It carries the number no source can give them: how many of the names they
// handed over nothing else found. That is the reason to hand a list over at
// all — a host in it that no log, register, zone or record named is a host the
// outside cannot see, and it is the line somebody reading their own estate
// came here for.
function saysKnown(data) {
  const r = data.known || {};

  if (!r.asked) return "not given: no names were typed or loaded";
  if (r.reason) return "Not established: " + r.reason;
  // Names under another domain are left out, and said to be, as on the
  // command line.
  if (!r.named && r.foreign) return "none under this domain: " + r.foreign + " under other domains, left out";
  if (!r.named) return "named none of them";

  const alone = (data.names || []).filter(
    (n) => (n.sources || []).length === 1 && n.sources[0] === "operator"
  ).length;
  const foreign = r.foreign ? "; " + r.foreign + " under other domains, left out" : "";
  return (alone
    ? r.named + " given, " + alone + " of them named by nothing else"
    : r.named + " given, every one of them named by something else as well") + foreign;
}

// saysReverse is what the addresses in the ranges somebody named answered to.
//
// It was the one source with no line here, while the page offers the field
// that asks for it: an operator who typed a range got its names folded into
// the list with nothing saying the walk had happened, how wide it was, or that
// it had failed. Every other source says what it could not see, and a report
// where one of six is silent is a report whose totals cannot be read (R4).
//
// The count carries what was asked as well as what answered, because the
// difference is the shape of the range: a /24 with four answers is four
// machines and two hundred and fifty-two addresses nobody has named.
function saysReverse(data) {
  const r = data.reverse || {};

  if (!r.asked) return "not walked: no address range was named";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named && r.unread) return "named none of them in what was read; not read: " + r.unread;
  if (!r.named) return "named none of them";
  return "named " + r.named + " of them, off the reverse records in the ranges named" + notRead(r);
}

// saysPresented is what the hosts themselves said, in one line.
//
// It carries how many were asked and how many answered, because the difference
// is the measure of how much this could not see: an estate where two hosts in
// twenty presented a certificate has eighteen nobody here read.
function saysPresented(data) {
  const r = data.presented || {};

  if (!r.asked) return "not asked: this installation does not read them";
  if (r.reason) return "Not established: " + r.reason;
  if (!r.named && r.unread) return "named none of them in what was read; not read: " + r.unread;
  if (!r.named) return "named none of them";
  return "named " + r.named + " of them, off the certificates they presented" + notRead(r);
}

// recordSources are the record types that named something, in a fixed order.
function recordSources(data) {
  const out = [];
  for (const want of ["MX", "SPF", "NS"]) {
    if ((data.names || []).some((n) => (n.sources || []).indexOf(want) >= 0)) out.push(want);
  }
  return out;
}

// wordList joins names the way a sentence does.
function wordList(list) {
  if (!list.length) return "nothing";
  if (list.length === 1) return list[0];
  return list.slice(0, -1).join(", ") + " and " + list[list.length - 1];
}

// otherNames is what each source returned and dropped for belonging to
// somebody else, counted rather than listed.
function otherNames(logs, records) {
  if (logs && records) {
    return (logs + records) + " under other domains, not listed: " + logs +
      " on the same certificates, " + records + " in the records";
  }
  if (logs) return logs + " on the same certificates, under other domains, not listed";
  if (records) return records + " in the domain's own records, under other domains, not listed";
  return "";
}

// namedBy is the provenance column: everything that named one host, not the
// first thing that did.
function namedBy(name) {
  return (name.sources || []).join(", ");
}

// doingCell is what one name is doing, as a cell: the state on its own line
// and the evidence for it underneath.
//
// It was one sentence — "live — 192.0.2.1, 192.0.2.2, answering on 443 and
// 80" — in a column a reader is meant to run an eye down, and three addresses
// turned every such row into two lines of prose. The state is what somebody
// scans for, so the state is the cell; the evidence is a row-note, which is
// what the rest of this site calls a qualification of the cell above it. It
// stays in the row rather than moving to a fold, because a state with nothing
// behind it is a claim rather than a measurement (R17).
//
// Only "unchecked" is drawn faint, and that is deliberate. Faint here means
// nothing was measured, which is exactly what unchecked is. Greying "gone" or
// "dangling" would put a reading of an estate into a colour, and this mode
// grades nothing (R21) — the two states an operator is looking for are the
// last two that should recede.
function doingCell(name) {
  const now = name.now;
  if (!now) return el("td", "mark-faint", "unchecked");

  const cell = el("td", null, now.status || "unchecked");
  const why = doingWhy(now);
  if (why) cell.appendChild(el("p", "row-note", why));
  return cell;
}

// doingWhy is the evidence behind one state, without repeating the state.
function doingWhy(now) {
  const where = addressList(now);
  switch (true) {
    case Boolean(now.reason):
      return now.reason;
    case now.status === "dangling":
      return "an alias to " + now.alias + ", which does not resolve";
    case now.status === "unclaimed":
      return "an alias to " + now.alias + ", which " + now.provider + " answers as a name nobody has claimed there";
    case now.status === "gone":
      return "does not resolve";
    case now.status === "internal":
      return where + ", which nothing here may dial, and a resolver elsewhere may answer differently";
    case now.status === "live":
      return where + ", answering on " + (now.answered || []).join(" and ");
    case !now.status:
      return "nothing asked what this name is doing";
    default:
      return where + ", nothing answered";
  }
}

// addressList is where a name points, bounded so that one name with forty
// addresses does not become the report.
function addressList(now) {
  const show = 3;
  const all = now.addresses || [];
  const out = all.slice(0, show);
  if (all.length > show) out.push("and " + (all.length - show) + " more");
  return now.alias ? out.join(", ") + " via " + now.alias : out.join(", ");
}

// covered is the window the logs show one name in.
//
// The expiry is the useful end: a name whose newest certificate ran out two
// years ago is either gone or is now under a wildcard, and an operator reading
// their own estate is usually looking for exactly those. Which of the two it
// is, this does not say — nothing here asked the host anything.
// loggedWindow reports whether a log ever carried this name, which decides
// whether the cell beside it is a measurement or an absence.
function loggedWindow(name) {
  return Boolean(name.lastSeen) && !name.lastSeen.startsWith("0001-01-01");
}

function covered(name, data) {
  // A date the service does not have is absent, not the first day of year one.
  // It was the latter until 2026-09-27, because `omitempty` does nothing for a
  // time in Go — and this drew "certificates to 0001-01-01" beside a host a
  // reverse record named. The guard stays on this side as well: a reader of
  // this page cannot check what a service sent it.
  if (!name.lastSeen || name.lastSeen.startsWith("0001-01-01")) {
    // A name only the domain's own records carried was never in a
    // certificate, so it has no window rather than an empty one — and saying
    // "no dates in the log" would suggest a log had it and lost them.
    if ((name.sources || []).indexOf("certificate") >= 0) return "no dates in the log";
    // Said of what the logs returned, and only where they were read. Until
    // 2026-10-25 this read "in no logged certificate" whether or not the logs
    // had been asked, and of a search that is bounded (R4).
    const logs = (data && data.logs) || {};
    if (!logs.asked) return "the logs were not asked";
    if (logs.reason) return "not known: the logs were not read";
    if (data.truncated) return "not in the certificates listed, which are not all of them";
    return "not in the certificates the logs returned";
  }
  const to = "certificates to " + name.lastSeen.slice(0, 10);
  return name.firstSeen ? "from " + name.firstSeen.slice(0, 10) + ", " + to : to;
}

// namesLimits is printed under every inventory, including the tidy ones.
//
// Under the short clean ones especially: those are where a reader is most
// inclined to take the list for the estate.
function namesLimits(data) {
  const wrap = document.createDocumentFragment();
  wrap.appendChild(sectionTitle("What this does not show"));

  // The same list styling every other note on a report uses, rather than a
  // class of its own: this is a note, and a note that looked different would
  // read as a disclaimer somebody added later.
  const list = el("ul", "notes");
  const item = (text) => list.appendChild(el("li", null, text));

  // Each source speaks for itself, and only where it answered. A paragraph
  // about what a certificate log misses, printed under a report where the
  // monitor was never reached, describes the limits of something that did not
  // happen.
  item("Nothing here was guessed: no name was invented and no list of names was tried.");

  if (answered(data.logs)) {
    // Each sentence is one string rather than a concatenation, because both
    // faces of this report are compared for exactly these words and a claim
    // split across a `+` is a claim a reader of the source cannot find (R16).
    item(
      "From the public logs, these names were published by whoever obtained a certificate for them."
    );
    item(
      "A host with no publicly trusted certificate never appears — plain HTTP, a " +
        "service that is not HTTPS, or anything behind a private authority leaves " +
        "no trace in a public log."
    );
  }
  // Every record read, or the sentence says more than was: a domain whose
  // exchangers went unread has not been shown to take no mail.
  if (answered(data.records) && !data.records.unread) {
    item(
      "From the domain's own records, these are the hosts its mail, its sender policy and its delegation have to name. " +
        "A host that takes no mail, sends none and answers for no zone is in none of them."
    );
  }
  if (answered(data.zone) && (data.zone.named || 0) > 0) {
    item(
      "The zone handed itself over, so the names above are every name in it rather than a sample. " +
        "What is not in a zone is still not here: a host reached by address alone, and anything in a zone delegated away from this one."
    );
  }
  if (answered(data.presented)) {
    item(
      "The hosts that answered were asked for their certificates, which is how a name a private authority issued is found: no public log holds one. " +
        "A handshake was made and closed, nothing was requested over it, and the certificates were read rather than judged."
    );
  }
  if (answered(data.passive)) {
    item(
      "A passive register holds what somebody's resolver saw, not what this domain published. " +
        "A name in it may never have existed — a typo, or a name that resolved for an hour years ago — " +
        "and a host nobody outside ever looked up is not in it at all."
    );
  }
  if (data.probed) {
    item(
      "What each name is doing now was established by resolving it and opening a connection to each address it gave. " +
        "Nothing was sent over that connection, except to a name that points at a hosting service on a " +
        "fixed list, which was asked for its front page once."
    );
  }
  if (data.wildcards) {
    item(
      "A wildcard covers hosts without naming them, and " +
        data.wildcards +
        (data.wildcards === 1
          ? " of the names above is a wildcard."
          : " of the names above are wildcards.")
    );
    if (!answered(data.passive)) {
      // Half a sentence is the danger: a reader told that a wildcard hides
      // hosts, and not told that nothing went looking for them, is left
      // believing the report tried.
      item("Nothing here looked behind them: a passive register is the source that can, and none was named.");
    }
  }
  item(
    "This is an inventory, not a verdict: nothing above is graded, because no " +
      "document says which names an estate ought to have."
  );

  // And, on the demonstration, where the sources it does not use can be used.
  //
  // This deployment reaches hosts compiled into it (N6) and configures two of
  // the six sources, so a visitor sees four lines saying "not asked" with no
  // way to change any of them — which reads as four things the tool cannot do
  // rather than four it was not asked to do here. It points at the lines the
  // report already drew rather than listing them again: a second list would be
  // a second thing to keep in step with what is actually configured, and the
  // day it drifted it would be this page telling somebody something false
  // about the tool (N14).
  if (DEMO_SITE) {
    item(
      "Every source above marked not asked is one this demonstration does not use: it reaches " +
        "only hosts compiled into it, so there is no field here for a zone, a register, or an " +
        "address range. A copy you run yourself reads each of them, for domains you have shown " +
        "control of."
    );
  }

  wrap.appendChild(list);
  return wrap;
}

/*
  Updates: whether a newer signed release exists, and how to install it.

  Nothing here asks GitHub. The page asks this installation, which answers
  with what its last check found; only Check now and the daily switch under
  This installation make it ask, and it believes the answer only if the
  release key signed it (internal/updates). The version is the one thing
  taken from that answer, and it is used only once it reads as a release
  name: in the banner's words, in the link to the release's notes, and in
  the commands. Every other character of the commands is written here.

  The commands install nothing from the page. They run on the server, in
  the operator's own terminal, and check the signature again there with the
  key written below, so a page that was lied to can at worst show a banner.
  Each line is safe on its own, because a pasted line runs whether or not
  the one before it worked: the files go into a folder of their own named
  for the version, the folder is made only where the compose file is, and
  the compose file in use is replaced in the one line that first checks the
  signature, that the signed list is this version's and not an older one's,
  and the file's digest.

  They leave nothing behind. Once the new version has started, the same line
  removes the folder and every Porch image no container uses, chosen by the
  label every Porch image carries, so no other image on the server is
  touched; a download that does not verify is removed too. The compose file
  replaced is not kept: going back is the same lines for the older release,
  checked the same way.
*/
const RELEASE_NAME = /^v\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const RELEASE_SIGNER = "releases@denyfirst.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDD7Ie9zRf76RynH052/Abkv5k2nzosQd2DihyQMixVR";
const RELEASE_FINGERPRINT = "SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y";
const RELEASE_PAGE = "https://github.com/denyfirst/porch/releases/";
const RELEASE_LABEL = "org.opencontainers.image.source=https://github.com/denyfirst/porch";

// The lines, as pieces a terminal would colour: [class, text], or text.
function updateCommands(version) {
  if (!RELEASE_NAME.test(version)) return null;
  const dir = "update-" + version;
  const C = t => ["t-c", t], F = t => ["t-f", t], S = t => ["t-s", t], O = t => ["t-o", t];
  return [
    [C("test"), " ", F("-f"), " docker-compose.yml ", O("&&"), " ", C("mkdir"), " ", F("-p"), " " + dir],
    [C("for"), " f ", C("in"), " docker-compose.yml SHA256SUMS SHA256SUMS.sig", O(";"), " ", C("do"), " ",
      C("curl"), " ", F("-fsSL"), " ", F("-o"), " ", S("\"" + dir + "/${f}\""), " ",
      S("\"" + RELEASE_PAGE + "download/" + version + "/${f}\""), O(";"), " ", C("done")],
    [C("echo"), " ", S("'" + RELEASE_SIGNER + "'"), " ", O(">"), " " + dir + "/allowed_signers"],
    [C("if"), " ", C("ssh-keygen"), " ", F("-Y"), " verify ", F("-f"), " " + dir + "/allowed_signers ",
      F("-I"), " releases@denyfirst.dev ", F("-n"), " file ", F("-s"), " " + dir + "/SHA256SUMS.sig ",
      O("<"), " " + dir + "/SHA256SUMS ", O("&&"), " ",
      C("grep"), " ", F("-qF"), " ", S("'_" + version + "_'"), " " + dir + "/SHA256SUMS ", O("&&"), " ",
      O("("), C("cd"), " " + dir + " ", O("&&"), " ", C("sha256sum"), " ", F("--ignore-missing"), " ", F("-c"), " SHA256SUMS", O(")"),
      O(";"), " ", C("then"), " ",
      C("cp"), " " + dir + "/docker-compose.yml docker-compose.yml ", O("&&"), " ",
      C("sudo"), " ", C("docker"), " compose up ", F("-d"), " ", O("&&"), " ",
      C("rm"), " ", F("-r"), " " + dir + " ", O("&&"), " ",
      C("sudo"), " ", C("docker"), " image prune ", F("-a"), " ", F("-f"), " ", F("--filter"), " label=" + RELEASE_LABEL, O(";"), " ",
      C("else"), " ", C("rm"), " ", F("-rf"), " " + dir, O(";"), " ",
      C("echo"), " ", S("'STOP: " + version + " did not verify; its download was removed and nothing was changed'"), O(";"), " ", C("fi")],
  ];
}

function drawCommands(code, lines) {
  clear(code);
  lines.forEach((line, i) => {
    if (i > 0) code.appendChild(document.createTextNode("\n"));
    const ln = el("span", "ln");
    for (const piece of line) {
      if (typeof piece === "string") ln.appendChild(document.createTextNode(piece));
      else ln.appendChild(el("span", piece[0], piece[1]));
    }
    code.appendChild(ln);
  });
}

// When a check ran, as the page says it: "2026-10-12 09:14 UTC".
function checkedWhen(at) {
  const m = typeof at === "string" && /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}):\d{2}Z$/.exec(at);
  return m ? m[1] + " " + m[2] + " UTC" : null;
}

// The answer, read as this page needs it and nothing more: a version that is
// not a release name is no version.
function readUpdates(data) {
  const d = data && typeof data === "object" ? data : {};
  const latest = typeof d.latest === "string" && RELEASE_NAME.test(d.latest) ? d.latest : "";
  return {
    running: typeof d.running === "string" ? d.running.slice(0, 64) : "",
    latest,
    newer: d.newer === true && latest !== "",
    daily: d.daily === true,
    tampered: d.tampered === true,
    error: typeof d.error === "string" ? d.error.slice(0, 300) : "",
    checked: checkedWhen(d.checkedAt),
  };
}

const UPDATES_WAIT = 30000;

async function updatesRequest(method, path, body) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), UPDATES_WAIT);
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
      cache: "no-store",
      signal: abort.signal,
    });
  } catch {
    throw new Error("The installation could not be reached. Try again.");
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Sign in to use this installation.");
  }
  let data = null;
  try {
    data = await response.json();
  } catch {
    throw new Error("The installation sent something this page could not read.");
  }
  if (!response.ok) {
    const error = data && data.error ? data.error : {};
    throw new Error(typeof error.message === "string" ? error.message : "The installation did not answer as expected.");
  }
  return readUpdates(data);
}

// New check: the banner, when the last check found a newer release, or a
// warning, when the list GitHub served did not verify. Nothing otherwise.
function showUpdateBanner(state) {
  const banner = document.getElementById("update-banner");
  const text = document.getElementById("update-text");
  const tag = document.getElementById("update-tag");
  const notes = document.getElementById("update-notes");
  const how = document.getElementById("update-how");
  clear(text);

  if (state.tampered) {
    tag.textContent = "Warning";
    text.appendChild(el("strong", null, "Do not update now."));
    text.appendChild(document.createTextNode(
      " The release list GitHub served" + (state.checked ? " at " + state.checked : "") +
      " does not verify with the release key, so it may not be the project's. " +
      "Check a release by hand as docs/verify.md says before installing anything."));
    notes.hidden = true;
    how.hidden = true;
    banner.hidden = false;
    return;
  }

  const lines = state.newer ? updateCommands(state.latest) : null;
  if (!lines) {
    banner.hidden = true;
    return;
  }
  tag.textContent = "Update";
  text.appendChild(el("strong", null, "Porch " + state.latest + " is available."));
  text.appendChild(document.createTextNode(
    " Its signed list verified with the release key; this installation runs " + state.running + "."));

  // What the last check found, and when: a banner is never refreshed by
  // loading the page, which asks GitHub nothing, so a newer release than this
  // one may exist since. The way to look again is named, not taken.
  const again = document.createElement("a");
  again.href = "/installation#updates";
  again.textContent = "This installation";
  text.appendChild(document.createTextNode(
    " Found by the check" + (state.checked ? " at " + state.checked : "") + "; Check now under "));
  text.appendChild(again);
  text.appendChild(document.createTextNode(" looks for anything newer."));
  notes.href = RELEASE_PAGE + "tag/" + state.latest;
  notes.hidden = false;

  const note = document.getElementById("update-note");
  clear(note);
  for (const piece of [
    "Run them on the server, in the folder the compose file is in. They download " + state.latest +
      "'s compose file and signed list into ", ["update-" + state.latest],
    ", check the signature with the key written into this page and that the list is " + state.latest +
      "'s, and only then put the new compose file in place of the one in use and restart. Once it has " +
      "started they remove that folder and every Porch image no container uses, so nothing is left behind. " +
      "If anything does not verify they remove the folder, print STOP and change nothing else. " +
      "Changes of your own belong in ",
    ["docker-compose.override.yml"],
    ", which Docker Compose reads beside it and an update leaves alone.",
  ]) {
    note.appendChild(typeof piece === "string" ? document.createTextNode(piece) : el("code", null, piece[0]));
  }
  drawCommands(document.getElementById("update-commands"), lines);
  how.hidden = false;
  banner.hidden = false;
}

const updateBanner = document.getElementById("update-banner");
if (updateBanner && !DEMO_SITE) {
  updatesRequest("GET", "/api/v1/updates").then(showUpdateBanner, () => {
    // No answer is no banner: this page is for checking names, and whether
    // the installation could say is shown under This installation.
  });
}

// This installation: what runs, what the last check found, Check now, and
// the daily check.
function showUpdates(state) {
  document.getElementById("updates-running").textContent = state.running || "Not known.";

  const latest = document.getElementById("updates-latest");
  clear(latest);
  if (state.latest) {
    latest.appendChild(el("strong", null, state.latest));
    const said = state.latest === state.running ? ", the one this installation runs."
      : state.newer ? ", newer than this one."
        : RELEASE_NAME.test(state.running) ? ", not newer than this one."
          : ". This build is not a release, so whether it is behind is not said.";
    latest.appendChild(document.createTextNode(said + " Signed by the release key "));
    latest.appendChild(el("code", "key-fingerprint", RELEASE_FINGERPRINT));
    latest.appendChild(document.createTextNode(state.checked ? "; checked " + state.checked + "." : "."));
    // Where to go from here, when there is somewhere: the commands are drawn
    // on New check, beside the banner that announces them.
    if (state.newer) {
      const go = document.createElement("a");
      go.href = "/";
      go.textContent = "New check";
      latest.appendChild(document.createTextNode(" The commands to install it are on "));
      latest.appendChild(go);
      latest.appendChild(document.createTextNode("."));
    }
  } else {
    // A check that failed is said as failed, with its reason on the line below.
    // "Found nothing it could believe" was printed for GitHub being out of
    // reach as well, which is no statement about the list (live test,
    // 2026-10-20).
    latest.textContent = !state.checked ? "Not checked yet."
      : state.error ? "Not known: the last check failed."
        : "Not known: the last check found nothing it could believe.";
  }

  // The reason a check failed is the installation's own sentence, from a
  // fixed list (internal/updates); a tampered list is said first.
  document.getElementById("updates-status").textContent = state.error
    ? (state.checked ? "The check at " + state.checked + " failed: " : "The last check failed: ") + state.error + "."
    : "";

  const daily = document.getElementById("updates-daily");
  daily.checked = state.daily;
  daily.disabled = false;
  document.getElementById("updates-daily-state").textContent = state.daily ? "On." : "Off.";
  document.getElementById("updates-check").disabled = false;
}

const updatesCheck = document.getElementById("updates-check");
if (updatesCheck && !DEMO_SITE) {
  const status = document.getElementById("updates-status");
  const daily = document.getElementById("updates-daily");

  updatesRequest("GET", "/api/v1/updates").then(showUpdates, err => {
    status.textContent = err.message;
  });

  updatesCheck.addEventListener("click", async () => {
    updatesCheck.disabled = true;
    status.textContent = "Checking with GitHub…";
    try {
      showUpdates(await updatesRequest("POST", "/api/v1/updates/check"));
    } catch (err) {
      status.textContent = err.message;
    } finally {
      updatesCheck.disabled = false;
    }
  });

  daily.addEventListener("change", async () => {
    const wanted = daily.checked;
    daily.disabled = true;
    try {
      showUpdates(await updatesRequest("POST", "/api/v1/updates/daily", { daily: wanted }));
    } catch (err) {
      // Not kept is shown as not kept: the switch goes back to what is.
      daily.checked = !wanted;
      status.textContent = err.message;
    } finally {
      daily.disabled = false;
    }
  });
}
