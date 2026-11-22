import init, * as wasm from "./pkg/contaminate_web.js";

const WASM_URL = new URL("./pkg/contaminate_web_bg.wasm", import.meta.url);
// Lists fetched only when selected. `hashes` holds the EICAR test signature,
// which antivirus software is built to flag.
const LAZY_LISTS = new Set(["hashes"]);
const ROW_LIMIT = 5000;

// ---------------------------------------------------------------------------
// DOM helpers. Text always goes in as text nodes: the wordlists contain
// phishing lures and prompt-injection probes, and analyzed files can contain
// anything.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;
    else if (k in e) e[k] = v;
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null && c !== false) e.append(c);
  return e;
}

/** Text with control and format characters (zero-width, bidi overrides, …) made visible. */
function visible(s) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const m of s.matchAll(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu)) {
    frag.append(s.slice(last, m.index));
    const cp = m[0].codePointAt(0);
    const shown = cp === 9 ? "\\t" : `\\u{${cp.toString(16)}}`;
    frag.append(el("span", { class: "esc", title: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}` }, shown));
    last = m.index + m[0].length;
  }
  frag.append(s.slice(last));
  return frag;
}

const hex = (n, w = 0) => "0x" + n.toString(16).padStart(w, "0");
const fmt = (n) => n.toLocaleString("en-US");
const bytesLabel = (n) => (n < 10240 ? `${fmt(n)} B` : `${fmt(Math.round(n / 1024))} KiB`);

function setStatus(node, text, kind = "") {
  node.textContent = text;
  node.className = `status ${kind}`;
}

/** Same rules as `contaminate::parse_wordlist`. */
function parseWordlist(text) {
  return text
    .replace(/^﻿/, "")
    .split("\n")
    .map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l))
    .filter((l) => l !== "" && !l.startsWith("#"));
}

/** The comment block at the top of a list file, as one paragraph. */
function describe(text) {
  const out = [];
  for (const line of text.replace(/^﻿/, "").split("\n")) {
    if (!line.startsWith("#")) break;
    out.push(line.replace(/^#\s?/, ""));
  }
  return out.join(" ").trim();
}

function parseKeys(text) {
  const keys = [];
  for (const part of text.split(/[\s,]+/).filter(Boolean)) {
    const n = /^0x/i.test(part) ? parseInt(part.slice(2), 16) : parseInt(part, 10);
    if (!Number.isInteger(n) || n < 0 || n > 255 || !/^(0x[0-9a-f]+|\d+)$/i.test(part)) {
      throw new Error(`bad XOR key "${part}" (want 0–255)`);
    }
    keys.push(n);
  }
  return Uint8Array.from(keys);
}

function rustChar(cp) {
  const named = { 0: "\\0", 9: "\\t", 10: "\\n", 13: "\\r", 39: "\\'", 92: "\\\\" };
  if (cp in named) return `'${named[cp]}'`;
  const c = String.fromCodePoint(cp);
  return /[\p{L}\p{N}\p{P}\p{S} ]/u.test(c) ? `'${c}'` : `'\\u{${cp.toString(16)}}'`;
}

function table(headers, rows, numeric = []) {
  return el("div", { class: "scroll" },
    el("table", {},
      el("thead", {}, el("tr", {}, headers.map((h, i) => el("th", { class: numeric.includes(i) ? "num" : "" }, h)))),
      el("tbody", {}, rows)));
}

// ---------------------------------------------------------------------------
// Startup

let selfBytes;
const lists = new Map(); // name -> { name, text, words, description, embedded, lazy, loaded }

async function main() {
  try {
    const res = await fetch(WASM_URL);
    if (!res.ok) throw new Error(`fetching ${WASM_URL.pathname}: HTTP ${res.status}`);
    selfBytes = new Uint8Array(await res.arrayBuffer());
    // Instantiate from the very bytes we analyze (a copy: instantiation may
    // hold on to its input).
    await init({ module_or_path: selfBytes.slice() });
  } catch (e) {
    setStatus($("#self-status"), `Couldn't load the module: ${e.message}`, "bad");
    return;
  }
  selfCheck();
  await loadLists();
  setupPlayground();
  setupAnalyzer();
}

// ---------------------------------------------------------------------------
// Self-check

const SECTION_KIND = (name) =>
  name.startsWith("data") ? "data" : name.startsWith("custom:") ? "custom" : name === "code" ? "code" : "other";

function selfCheck() {
  const report = JSON.parse(wasm.locate_copies(selfBytes));
  const ok = report.copies.filter((c) => c.found.length > 0).length;
  setStatus(
    $("#self-status"),
    `${ok} of ${report.copies.length} copies found in contaminate_web_bg.wasm (${bytesLabel(report.size)}, ${report.format}).`,
    ok === report.copies.length ? "good" : "bad",
  );
  $("#self-source").textContent = wasm.copies_source();

  // Module map: sections to scale, with a tick at each copy.
  const map = $("#self-map");
  for (const [name, start, end] of report.sections) {
    map.append(el("div", {
      class: `sec ${SECTION_KIND(name)}`,
      style: `left:${(100 * start) / report.size}%;width:${(100 * (end - start)) / report.size}%`,
      title: `${name}: ${hex(start)}–${hex(end)} (${bytesLabel(end - start)})`,
    }));
  }
  report.copies.forEach((c, i) => {
    for (const f of c.found) {
      map.append(el("div", {
        class: `tick c${i}`,
        style: `left:${(100 * f.offset) / report.size}%;width:max(3px, ${(100 * c.bytes) / report.size}%)`,
        title: `${c.name} at ${hex(f.offset)} in ${f.section}`,
      }));
    }
  });
  $("#self-legend").append(
    ...["code", "data", "custom", "other"].map((k) => el("span", {}, el("i", { class: `sw sec ${k}` }), k === "data" ? "data segments" : k === "custom" ? "custom sections" : k)),
    ...report.copies.map((c, i) => el("span", {}, el("i", { class: `sw tick c${i}` }), c.name)),
  );

  const tbody = $("#self-copies tbody");
  report.copies.forEach((c, i) => {
    const s = c.settings;
    const settings = [
      s.encoding,
      s.terminator == null ? "no terminator" : `${rustChar(s.terminator)} after each word`,
      s.xor ? `XOR ${hex(s.xor, 2)}` : null,
      s.repeat > 1 ? `×${s.repeat}` : null,
    ].filter(Boolean).join(" · ");
    const found = c.found.length
      ? c.found.map((f) => el("div", {}, el("code", {}, hex(f.offset)), " in ", el("code", {}, f.section)))
      : el("span", { class: "bad" }, "not found");
    tbody.append(el("tr", {},
      el("td", {}, el("i", { class: `sw tick c${i}` }), el("code", {}, c.name)),
      el("td", {}, settings),
      el("td", { class: "num" }, fmt(c.bytes)),
      el("td", {}, found)));
  });

  // Word search over the whole module.
  const words = JSON.parse(wasm.embedded_words());
  const result = JSON.parse(wasm.find_words(selfBytes, words.join("\n"), Uint8Array.of()));
  const byEnc = new Map();
  for (const w of result.words) {
    for (const f of w.found) {
      const e = byEnc.get(f.encoding) ?? { words: 0, sections: new Map() };
      e.words++;
      for (const [s, n] of Object.entries(f.sections)) e.sections.set(s, (e.sections.get(s) ?? 0) + n);
      byEnc.set(f.encoding, e);
    }
  }
  const missing = result.words.filter((w) => w.found.length === 0).length;
  $("#self-words-status").textContent =
    `${fmt(words.length - missing)} of ${fmt(words.length)} embedded words found.` +
    (missing ? ` ${missing} missing: words shorter than 8 bytes are only tried without XOR.` : "");
  const tb = $("#self-words tbody");
  const sorted = [...byEnc].sort((a, b) => b[1].words - a[1].words);
  // Brute-forcing 256 keys turns up a few chance matches; fold them into one row.
  const major = sorted.filter(([, e]) => e.words >= 5);
  const minor = sorted.filter(([, e]) => e.words < 5);
  for (const [enc, e] of major) {
    tb.append(el("tr", {},
      el("td", {}, el("code", {}, enc)),
      el("td", { class: "num" }, fmt(e.words)),
      el("td", {}, [...e.sections].map(([s, n]) => `${s} ×${fmt(n)}`).join(", "))));
  }
  if (minor.length) {
    tb.append(el("tr", { class: "dim" },
      el("td", {}, `${minor.length} more`),
      el("td", { class: "num" }, "<5 each"),
      el("td", {}, "chance matches under keys no copy uses: ", el("code", {}, minor.map(([enc]) => enc).join(" ")))));
  }
  $("#self-body").hidden = false;
}

// ---------------------------------------------------------------------------
// Wordlists

async function loadLists() {
  const names = await (await fetch("wordlists/index.json")).json();
  const embedded = new Set(JSON.parse(wasm.embedded_words()));
  await Promise.all(names.map(async (name) => {
    const entry = { name, lazy: LAZY_LISTS.has(name), loaded: false, words: [], text: "", description: "" };
    lists.set(name, entry);
    if (!entry.lazy) await fetchList(entry, embedded);
  }));
  // Keep index order (fetches finish in any order).
  const ul = $("#lists");
  ul.replaceChildren();
  for (const name of names) {
    const l = lists.get(name);
    const box = el("input", { type: "checkbox", value: name, checked: name === "canary" });
    const count = el("span", { class: "count" }, l.loaded ? fmt(l.words.length) : "?");
    const li = el("li", { title: l.description || (l.lazy ? "Contains the EICAR antivirus test signature; fetched only when selected." : "") },
      el("label", {}, box, el("code", {}, name), count, l.lazy ? el("span", { class: "warn" }, "EICAR") : null));
    l.countNode = count;
    l.liNode = li;
    if (l.embedded) li.classList.add("embedded");
    ul.append(li);
  }
}

async function fetchList(entry, embedded) {
  entry.text = await (await fetch(`wordlists/${entry.name}.txt`)).text();
  entry.words = parseWordlist(entry.text);
  entry.description = describe(entry.text);
  entry.embedded = embedded ? entry.words.every((w) => embedded.has(w)) : false;
  entry.loaded = true;
}

async function selectedText() {
  const names = $$("#lists input:checked").map((b) => b.value);
  const parts = [];
  for (const name of names) {
    const l = lists.get(name);
    if (!l.loaded) {
      await fetchList(l);
      l.countNode.textContent = fmt(l.words.length);
      l.liNode.title = l.description;
    }
    parts.push(l.text);
  }
  parts.push($("#custom-words").value);
  return { names, text: parts.join("\n") };
}

// ---------------------------------------------------------------------------
// Playground

let playBytes = new Uint8Array();
let playText = "";
let playXor = 0;
let activeTab = "hex";

function readSettings() {
  const encoding = $("#set-encoding").value;
  const termSel = $("#set-term").value;
  let terminator;
  if (termSel === "custom") {
    const c = $("#set-term-custom").value;
    if (!c) throw new Error("enter a custom terminator character");
    terminator = c.codePointAt(0);
  } else if (termSel !== "none") {
    terminator = Number(termSel);
  }
  const repeat = Math.min(64, Math.max(1, parseInt($("#set-repeat").value, 10) || 1));
  const keys = parseKeys($("#set-xor").value || "0");
  if (keys.length !== 1) throw new Error("enter one XOR key");
  return { encoding, terminator, repeat, xor: keys[0] };
}

function snippet(s, names, custom) {
  const fields = [];
  const ENC = { utf8: "Utf8", utf16le: "Utf16Le", utf16be: "Utf16Be" };
  if (s.encoding !== "utf8") fields.push(`    encoding: Encoding::${ENC[s.encoding]},`);
  if (s.terminator !== 0) fields.push(`    terminator: ${s.terminator == null ? "None" : `Some(${rustChar(s.terminator)})`},`);
  if (s.repeat !== 1) fields.push(`    repeat: ${s.repeat},`);
  if (s.xor !== 0) fields.push(`    xor: ${hex(s.xor, 2)},`);

  const lines = [];
  const features = names.map((n) => `"wordlist-${n}"`);
  const dep = names.length === 1 && names[0] === "canary"
    ? `contaminate = "0.1"`
    : `contaminate = { version = "0.1", ${names.includes("canary") ? "" : "default-features = false, "}features = [${features.join(", ")}] }`;
  lines.push("# Cargo.toml", dep);
  if (custom) lines.push("# plus your words: CONTAMINATE_WORDLIST=my-words.txt cargo build");
  lines.push("", "// main.rs");
  if (fields.length === 0) {
    lines.push("contaminate::contaminate!();");
  } else {
    const uses = ["contaminate", "Settings", ...(s.encoding !== "utf8" ? ["Encoding"] : [])];
    lines.push(`use contaminate::{${uses.join(", ")}};`, "",
      "const MINE: Settings = Settings {", ...fields, "    ..Settings::DEFAULT", "};", "",
      "contaminate!(settings = MINE);");
  }
  return lines.join("\n");
}

let playSeq = 0;
async function updatePlayground() {
  const seq = ++playSeq;
  const status = $("#play-status");
  $("#set-term-custom-wrap").hidden = $("#set-term").value !== "custom";
  let s, sel;
  try {
    s = readSettings();
    sel = await selectedText();
    if (seq !== playSeq) return; // a newer update started while fetching
    playText = sel.text;
    playXor = s.xor;
    playBytes = wasm.encode(sel.text, s.encoding, s.terminator, s.repeat, s.xor);
  } catch (e) {
    setStatus(status, e.message, "bad");
    return;
  }
  const words = parseWordlist(sel.text).length;
  $("#snippet").textContent = snippet(s, sel.names, parseWordlist($("#custom-words").value).length > 0);
  setStatus(status, `${fmt(words)} words × ${s.repeat} → ${fmt(playBytes.length)} bytes embedded per invocation.`);
  renderTab();
}

function renderTab() {
  const out = $("#play-out");
  for (const b of $$(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === activeTab));
  if (playBytes.length === 0) {
    out.replaceChildren(el("p", { class: "note" }, "No words selected."));
    return;
  }
  if (activeTab === "hex") out.replaceChildren(hexdump(playBytes, 4096));
  else if (activeTab === "words") {
    out.replaceChildren(el("ol", { class: "words" }, parseWordlist(playText).map((w) => el("li", {}, visible(w)))));
  } else {
    const xor = playXor;
    const plain = activeTab === "strings";
    const r = JSON.parse(wasm.extract(playBytes, 4, plain ? "utf8" : "utf8,utf16le,utf16be", plain ? Uint8Array.of() : Uint8Array.of(xor), 2000));
    const intro = plain
      ? "UTF-8 runs of 4+ printable characters, without undoing any XOR. Roughly what strings -e S prints."
      : `All three encodings, plus XOR key ${hex(xor, 2)} undone. What the analyze example prints with -x ${hex(xor, 2)}.`;
    const body = r.total === 0
      ? el("p", { class: "bad" }, "Nothing. This tool finds no text in these bytes.")
      : el("pre", { class: "strings" }, r.hits.map((h) =>
          el("div", {}, el("span", { class: "dim" }, `${hex(h.offset, 6)}  ${h.encoding.padEnd(12)} `), visible(h.text))));
    out.replaceChildren(el("p", { class: "note" }, intro, r.total ? ` ${fmt(r.total)} strings${r.total > r.hits.length ? `, first ${fmt(r.hits.length)} shown` : ""}.` : ""), body);
  }
}

function hexdump(bytes, max) {
  const lines = [];
  const n = Math.min(bytes.length, max);
  for (let off = 0; off < n; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, n));
    let h = "";
    let a = "";
    for (let i = 0; i < 16; i++) {
      h += i < row.length ? row[i].toString(16).padStart(2, "0") + " " : "   ";
      if (i === 7) h += " ";
      if (i < row.length) a += row[i] >= 0x20 && row[i] < 0x7f ? String.fromCharCode(row[i]) : ".";
    }
    lines.push(`${off.toString(16).padStart(8, "0")}  ${h} |${a}|`);
  }
  const frag = document.createDocumentFragment();
  frag.append(el("pre", { class: "hex" }, lines.join("\n")));
  if (bytes.length > max) frag.append(el("p", { class: "note" }, `First ${fmt(max)} of ${fmt(bytes.length)} bytes.`));
  return frag;
}

function setupPlayground() {
  let timer;
  const later = () => { clearTimeout(timer); timer = setTimeout(updatePlayground, 120); };
  $("#lists").addEventListener("change", updatePlayground);
  for (const id of ["set-encoding", "set-term"]) $(`#${id}`).addEventListener("change", updatePlayground);
  for (const id of ["set-term-custom", "set-repeat", "set-xor", "custom-words"]) $(`#${id}`).addEventListener("input", later);
  for (const b of $$(".tabs button")) {
    b.addEventListener("click", () => { activeTab = b.dataset.tab; renderTab(); });
  }
  updatePlayground();
}

// ---------------------------------------------------------------------------
// Analyzer

let file = null; // { name, bytes }

function setupAnalyzer() {
  const drop = $("#drop");
  $("#file-input").addEventListener("change", (e) => e.target.files[0] && loadFile(e.target.files[0]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
  });
  $("#use-self").addEventListener("click", () => { file = { name: "contaminate_web_bg.wasm", bytes: selfBytes }; runAnalyzer(); });
  $("#use-play").addEventListener("click", () => { file = { name: "playground bytes", bytes: playBytes }; runAnalyzer(); });
  for (const id of ["an-mode", "an-min", "an-xor"]) $(`#${id}`).addEventListener("change", runAnalyzer);
  $("#file .checks").addEventListener("change", runAnalyzer);
  $("#lists").addEventListener("change", () => $("#an-mode").value === "words" && runAnalyzer());
}

async function loadFile(f) {
  setStatus($("#an-status"), `Reading ${f.name}…`);
  file = { name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) };
  runAnalyzer();
}

async function runAnalyzer() {
  const status = $("#an-status");
  const out = $("#an-out");
  const mode = $("#an-mode").value;
  $("#file").classList.toggle("words-mode", mode === "words");
  if (!file) return;
  let keys;
  try {
    keys = parseKeys($("#an-xor").value);
  } catch (e) {
    setStatus(status, e.message, "bad");
    return;
  }
  setStatus(status, `Scanning ${file.name}…`);
  out.replaceChildren();
  // Let the status paint before the (synchronous) scan blocks the thread.
  await new Promise((r) => setTimeout(r, 30));
  const t0 = performance.now();
  const what = `${file.name}: ${fmt(file.bytes.length)} bytes`;
  if (mode === "strings") {
    const encs = $$("#file .checks input:checked").map((b) => b.value).join(",");
    if (!encs) { setStatus(status, "Pick at least one encoding.", "bad"); return; }
    const min = Math.max(1, parseInt($("#an-min").value, 10) || 4);
    const r = JSON.parse(wasm.extract(file.bytes, min, encs, keys, ROW_LIMIT));
    setStatus(status, `${what}, ${r.format}. ${fmt(r.total)} strings in ${Math.round(performance.now() - t0)} ms.`);
    renderStrings(out, r);
  } else {
    const { text } = await selectedText();
    const r = JSON.parse(wasm.find_words(file.bytes, text, keys));
    const missing = r.words.filter((w) => w.found.length === 0);
    setStatus(status,
      `${what}, ${r.format}. ${fmt(r.words.length - missing.length)} of ${fmt(r.words.length)} words found in ${Math.round(performance.now() - t0)} ms.`,
      missing.length ? "bad" : "good");
    renderWords(out, r);
  }
}

function renderStrings(out, r) {
  const counts = (obj) => table(["", "Strings"], Object.entries(obj).map(([k, n]) => el("tr", {}, el("td", {}, el("code", {}, k)), el("td", { class: "num" }, fmt(n)))), [1]);
  const filter = el("input", { type: "search", placeholder: "Filter strings…", class: "filter" });
  const rows = r.hits.map((h) => {
    const tr = el("tr", {},
      el("td", {}, el("code", {}, hex(h.offset, 8))),
      el("td", {}, el("code", {}, h.section)),
      el("td", {}, el("code", {}, h.encoding)),
      el("td", { class: "text" }, visible(h.text)));
    tr.dataset.search = `${h.text}\n${h.section}\n${h.encoding}`.toLowerCase();
    return tr;
  });
  const tbl = table(["Offset", "Section", "Encoding", "Text"], rows);
  filter.addEventListener("input", () => {
    const q = filter.value.toLowerCase();
    for (const tr of rows) tr.hidden = q !== "" && !tr.dataset.search.includes(q);
  });
  out.replaceChildren(
    el("div", { class: "counts" }, el("div", {}, el("h3", {}, "By section"), counts(r.by_section)), el("div", {}, el("h3", {}, "By encoding"), counts(r.by_encoding))),
    filter,
    r.total > r.hits.length ? el("p", { class: "note" }, `Showing the first ${fmt(r.hits.length)} of ${fmt(r.total)}.`) : null,
    tbl);
}

function renderWords(out, r) {
  const onlyMissing = el("input", { type: "checkbox" });
  const rows = r.words.map((w) => {
    const tr = el("tr", { class: w.found.length ? "" : "missing" },
      el("td", { class: "text" }, visible(w.word)),
      el("td", {}, w.found.length
        ? w.found.map((f) => el("div", {}, el("code", {}, f.encoding), ` ×${f.count} `,
            el("span", { class: "dim" }, Object.entries(f.sections).map(([s, n]) => `${s}×${n}`).join(", "))))
        : el("span", { class: "bad" }, "missing")));
    return tr;
  });
  onlyMissing.addEventListener("change", () => {
    for (const tr of rows) tr.hidden = onlyMissing.checked && !tr.classList.contains("missing");
  });
  out.replaceChildren(
    el("p", { class: "note" }, "Words from the playground's selection. Each is tried in every encoding; words of 8+ bytes under all 256 XOR keys, shorter ones only under the extra keys."),
    el("label", { class: "inline" }, onlyMissing, " Only missing words"),
    table(["Word", "Found as"], rows));
}

main();
