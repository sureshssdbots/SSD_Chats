const $ = id => document.getElementById(id);
const subtle = crypto.subtle, te = new TextEncoder(), td = new TextDecoder();
const RSA = { name: "RSA-OAEP", hash: "SHA-256" }, EC = { name: "ECDSA", namedCurve: "P-256" }, SIG = { name: "ECDSA", hash: "SHA-256" };
const S = { uid: null, dir: new Map(), keys: null, sel: null, msgs: new Map(), plain: new Map(), names: {}, handles: {}, started: false, tok: 0 };
let db = null, user = null, idleT = null;

const b64 = buf => { const b = new Uint8Array(buf); let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = t => { const s = atob(t.replace(/\s+/g, "")), o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i); return o; };
const lget = k => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : null; } catch (e) { return null; } };
const lset = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } };
const IDK = () => "securechat-id-" + S.uid, PINK = "securechat-pins", RK = "securechat-read", FK = "securechat-fail";

async function fpOf(d) {
  const h = new Uint8Array(await subtle.digest("SHA-256", te.encode(d.encPub + "|" + d.sigPub)));
  return (Array.from(h.slice(0, 8), x => x.toString(16).padStart(2, "0")).join("").match(/.{4}/g)).join(" ");
}
async function passKey(pass, salt) {
  const base = await subtle.importKey("raw", te.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function createIdentity(pass) {
  const e = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["wrapKey", "unwrapKey"]);
  const s = await subtle.generateKey(EC, true, ["sign", "verify"]);
  const plain = te.encode(JSON.stringify({ e: b64(await subtle.exportKey("pkcs8", e.privateKey)), s: b64(await subtle.exportKey("pkcs8", s.privateKey)) }));
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ep = b64(await subtle.encrypt({ name: "AES-GCM", iv }, await passKey(pass, salt), plain));
  return { v: 1, encPub: b64(await subtle.exportKey("spki", e.publicKey)), sigPub: b64(await subtle.exportKey("spki", s.publicKey)), salt: b64(salt), iv: b64(iv), ep };
}
async function unlockIdentity(rec, pass) {
  const j = JSON.parse(td.decode(await subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.iv) }, await passKey(pass, unb64(rec.salt)), unb64(rec.ep))));
  return {
    encPriv: await subtle.importKey("pkcs8", unb64(j.e), RSA, false, ["unwrapKey"]),
    sigPriv: await subtle.importKey("pkcs8", unb64(j.s), EC, false, ["sign"]),
    encPub: rec.encPub, sigPub: rec.sigPub
  };
}
const canon = m => ["v2", m.from, m.to, m.ts, m.n, m.iv, m.ct, m.wkTo, m.wkFrom].join("|");
function pack(text, ttl) {
  const j = te.encode(JSON.stringify({ t: text, x: ttl ? Date.now() + ttl : 0 }));
  const o = new Uint8Array(Math.max(256, Math.ceil((j.length + 4) / 256) * 256));
  new DataView(o.buffer).setUint32(0, j.length); o.set(j, 4); return o;
}
function unpack(buf) { const b = new Uint8Array(buf); return JSON.parse(td.decode(b.subarray(4, 4 + new DataView(b.buffer, b.byteOffset).getUint32(0)))); }
function strength(p) { return Math.min(p.length, 24) * 2 + (/[a-z]/.test(p) + /[A-Z]/.test(p) + /\d/.test(p) + /[^\w\s]/.test(p)) * 4 + (/\s/.test(p) ? 6 : 0); }
async function safety(a, b) {
  const h = new Uint8Array(await subtle.digest("SHA-256", te.encode([a, b].sort().join("|"))));
  return Array.from(h.slice(0, 10), x => String(x % 100).padStart(2, "0")).join("").match(/.{5}/g).join(" ");
}
function unread(id) { const r = (lget(RK) || {})[id] || 0; return [...S.msgs.values()].filter(m => m.from === id && m.to === S.uid && m.ts > r).length; }
function markRead() {
  if (!S.sel) return;
  const r = lget(RK) || {}, mx = Math.max(0, ...[...S.msgs.values()].filter(m => m.from === S.sel && m.to === S.uid).map(m => m.ts));
  if ((r[S.sel] || 0) < mx) { r[S.sel] = mx; lset(RK, r); renderContacts(); }
}

async function sendMsg(text) {
  const peer = S.dir.get(S.sel);
  const pubTo = await subtle.importKey("spki", unb64(peer.encPub), RSA, false, ["wrapKey"]);
  const pubMe = await subtle.importKey("spki", unb64(S.keys.encPub), RSA, false, ["wrapKey"]);
  const aes = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const m = {
    from: S.uid, to: S.sel, ts: Date.now(), n: b64(crypto.getRandomValues(new Uint8Array(16))), iv: b64(iv),
    ct: b64(await subtle.encrypt({ name: "AES-GCM", iv }, aes, pack(text, +$("ttl").value))),
    wkTo: b64(await subtle.wrapKey("raw", aes, pubTo, { name: "RSA-OAEP" })),
    wkFrom: b64(await subtle.wrapKey("raw", aes, pubMe, { name: "RSA-OAEP" }))
  };
  m.sig = b64(await subtle.sign(SIG, S.keys.sigPriv, te.encode(canon(m))));
  await db.collection("messages").add(m);
}
async function openMsg(id, m) {
  if (S.plain.has(id)) return S.plain.get(id);
  const mine = m.from === S.uid;
  const sk = mine ? S.keys.sigPub : (S.dir.get(m.from) || {}).sigPub;
  if (!sk) return { ok: false };
  let r;
  try {
    const vk = await subtle.importKey("spki", unb64(sk), EC, false, ["verify"]);
    if (!(await subtle.verify(SIG, vk, unb64(m.sig), te.encode(canon(m))))) throw 0;
    if (m.ts > Date.now() + 300000) throw 0;
    const aes = await subtle.unwrapKey("raw", unb64(mine ? m.wkFrom : m.wkTo), S.keys.encPriv, { name: "RSA-OAEP" }, { name: "AES-GCM" }, false, ["decrypt"]);
    const p = unpack(await subtle.decrypt({ name: "AES-GCM", iv: unb64(m.iv) }, aes, unb64(m.ct)));
    r = { ok: true, t: String(p.t), x: p.x || 0 };
  } catch (e) { r = { ok: false }; }
  S.plain.set(id, r);
  return r;
}

function nameOf(id) { return S.names[id] || "Someone"; }
async function loadNames(ids) {
  try {
    const ps = await user.profiles(ids);
    ids.forEach(i => { S.names[i] = (ps[i] && ps[i].name) || ""; S.handles[i] = (ps[i] && ps[i].handle) || ""; });
  } catch (e) {}
}
function renderContacts() {
  const ul = $("contacts"); ul.textContent = "";
  const cq = $("cSearch").value.trim().toLowerCase();
  const peers = [...S.dir.keys()].filter(i => i !== S.uid && (nameOf(i) + " " + (S.handles[i] || "")).toLowerCase().includes(cq.replace(/^@/, ""))).sort((a, b) => nameOf(a).localeCompare(nameOf(b)));
  $("empty").hidden = peers.length > 0;
  peers.forEach(id => {
    const li = document.createElement("li");
    li.className = "c" + (id === S.sel ? " on" : ""); li.tabIndex = 0;
    const av = document.createElement("div"); av.className = "av"; av.textContent = nameOf(id).charAt(0).toUpperCase() || "?";
    const nm = document.createElement("div"); nm.className = "cn"; nm.textContent = nameOf(id);
    const hd = document.createElement("small"); hd.textContent = "@" + (S.handles[id] || "unknown"); nm.append(hd);
    li.append(av, nm);
    const u = unread(id);
    if (u && id !== S.sel) { const b = document.createElement("span"); b.className = "badge"; b.textContent = u; li.append(b); }
    li.onclick = () => selectPeer(id);
    li.onkeydown = e => { if (e.key === "Enter") selectPeer(id); };
    ul.append(li);
  });
}
async function selectPeer(id) {
  S.sel = id; $("chat").classList.add("open");
  try { const f = await Backend.peer(id); if (f) S.dir.set(id, f); } catch (e) {}
  if (!S.dir.has(id)) return;
  $("chead").hidden = false; $("composer").hidden = false; $("mTools").hidden = false;
  $("peerName").textContent = nameOf(id) + " @" + (S.handles[id] || "unknown");
  const fp = await fpOf(S.dir.get(id));
  $("peerFp").textContent = "Fingerprint: " + fp;
  $("peerSn").textContent = "Safety number: " + await safety(await fpOf(S.keys), fp);
  const pins = lget(PINK) || {};
  if (!pins[id]) { pins[id] = fp; lset(PINK, pins); }
  const bad = S.dir.get(id).tl === "bad", changed = pins[id] !== fp || bad;
  $("tlwarn").hidden = !bad;
  const isV = (lget(VK) || {})[id] === fp;
  $("verifyBtn").textContent = isV ? "Verified ✓" : "Mark as verified"; $("verifyBtn").className = isV ? "ghost ok" : "ghost";
  $("keywarn").hidden = !changed; $("send").disabled = changed; $("txt").disabled = changed;
  renderContacts(); renderMsgs();
}
async function renderMsgs() {
  if (!S.sel || !S.keys) return;
  const tok = ++S.tok, box = $("msgs"), q = $("mSearch").value.trim().toLowerCase();
  let list = [...S.msgs.entries()].filter(([, m]) => (m.from === S.uid && m.to === S.sel) || (m.from === S.sel && m.to === S.uid)).sort((a, b) => a[1].ts - b[1].ts);
  const seen = new Set();
  list = list.filter(([, m]) => { const k = m.from + "|" + m.n; if (seen.has(k)) return false; seen.add(k); return true; });
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 80 || !box.firstChild || box.firstChild.className === "nosel";
  const nodes = [];
  for (const [id, m] of list) {
    const r = await openMsg(id, m);
    if (tok !== S.tok) return;
    if (r.ok && r.x && r.x < Date.now()) { if (m.from === S.uid) db.doc("messages/" + id).delete().catch(() => {}); continue; }
    if (q && !(r.ok && r.t.toLowerCase().includes(q))) continue;
    const d = document.createElement("div");
    d.className = "m" + (m.from === S.uid ? " me" : "") + (r.ok ? "" : " bad");
    d.textContent = r.ok ? r.t : "This message could not be verified (invalid signature or key). Hidden for your safety.";
    const t = document.createElement("span"); t.className = "meta";
    t.textContent = (r.ok ? "✓ verified · " : "⚠ ") + new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    d.append(t);
    if (m.from === S.uid) { const x = document.createElement("button"); x.className = "del"; x.textContent = "delete"; x.onclick = () => { if (confirm("Delete this message for everyone?")) db.doc("messages/" + id).delete(); }; t.append(x); }
    nodes.push(d);
  }
  if (!nodes.length) { const n = document.createElement("div"); n.className = "nosel"; n.textContent = "No messages yet. Send the first one."; nodes.push(n); }
  box.replaceChildren(...nodes);
  if (near) box.scrollTop = box.scrollHeight;
  markRead();
}

const CK = "securechat-contacts-", VK = "securechat-verified";
function contactIds() {
  const s = new Set(lget(CK + S.uid) || []);
  S.msgs.forEach(m => s.add(m.from === S.uid ? m.to : m.from));
  s.delete(S.uid);
  return [...s];
}
async function refreshContacts() {
  const ids = contactIds().filter(i => !S.dir.has(i));
  await Promise.all(ids.map(async i => { try { const d = await Backend.peer(i); if (d) S.dir.set(i, d); } catch (e) {} }));
  if (ids.length) await loadNames(ids);
  renderContacts();
}
async function addContact(id) {
  const l = new Set(lget(CK + S.uid) || []); l.add(id); lset(CK + S.uid, [...l]);
  await refreshContacts();
  if (S.dir.has(id)) selectPeer(id);
}
let searchTimer;
async function runSearch() {
  const q = $("cSearch").value.trim().toLowerCase().replace(/^@/, ""), ul = $("results");
  ul.textContent = "";
  if (!/^[a-z0-9_]{3,20}$/.test(q)) return;
  const rows = await Backend.search(q);
  rows.filter(r => r.id !== S.uid).forEach(r => {
    S.names[r.id] = r.name; S.handles[r.id] = r.handle;
    const li = document.createElement("li"); li.className = "c"; li.tabIndex = 0;
    const av = document.createElement("div"); av.className = "av"; av.textContent = (r.name || "?").charAt(0).toUpperCase();
    const nm = document.createElement("div"); nm.className = "cn"; nm.textContent = r.name;
    const hd = document.createElement("small"); hd.textContent = "@" + r.handle; nm.append(hd);
    const add = document.createElement("span"); add.className = "badge"; add.textContent = "Add";
    li.append(av, nm, add);
    li.onclick = () => { ul.textContent = ""; $("cSearch").value = ""; addContact(r.id); };
    ul.append(li);
  });
}
function startSync() {
  if (S.started) return; S.started = true;
  refreshContacts();
  const feed = snap => { snap.docChanges().forEach(c => { if (c.type === "removed") S.msgs.delete(c.doc.id); else S.msgs.set(c.doc.id, c.doc.data()); }); refreshContacts(); renderMsgs(); };
  db.collection("messages").where("to", "==", S.uid).onSnapshot(feed);
  db.collection("messages").where("from", "==", S.uid).onSnapshot(feed);
}
function showChat() {
  $("gate").hidden = true; $("chat").hidden = false; $("lockBtn").hidden = false;
  startSync(); renderContacts(); bumpIdle();
}
function lock() {
  S.keys = null; S.plain.clear(); S.sel = null; S.tok++;
  $("chat").hidden = true; $("chat").classList.remove("open"); $("lockBtn").hidden = true;
  $("msgs").replaceChildren(); $("chead").hidden = true; $("composer").hidden = true; $("mTools").hidden = true;
  showGate();
}
function bumpIdle() { clearTimeout(idleT); if (S.keys) idleT = setTimeout(lock, 10 * 60 * 1000); }
["pointerdown", "keydown"].forEach(ev => addEventListener(ev, bumpIdle));

function showGate() {
  const rec = lget(IDK());
  $("gate").hidden = false; $("gErr").textContent = ""; $("p1").value = $("p2").value = "";
  $("meter").hidden = true; $("p1").hidden = $("gBtn").hidden = false; $("p2").hidden = !!rec;
  $("gTitle").textContent = rec ? "Unlock your identity" : "Create your identity";
  $("gText").textContent = rec ? "Enter your passphrase. Your private keys stay on this device, locked by your passphrase."
    : "Choose a long passphrase (16+ characters or 5-6 random words). It locks your private keys on this device. If you forget it, it cannot be recovered.";
  $("gBtn").textContent = rec ? "Unlock" : "Create identity";
}
$("gBtn").onclick = async () => {
  const rec = lget(IDK()), p = $("p1").value;
  $("gErr").textContent = ""; $("gBtn").disabled = true;
  try {
    const lk = lget(FK) || { n: 0, until: 0 };
    if (rec && lk.until > Date.now()) { $("gErr").textContent = "Too many failed attempts. Try again in " + Math.ceil((lk.until - Date.now()) / 1000) + " seconds."; return; }
    if (!rec) {
      if (p.length < 12 || strength(p) < 36) { $("gErr").textContent = "Passphrase is too weak. Use 16+ characters or 5-6 random words."; return; }
      if (p !== $("p2").value) { $("gErr").textContent = "Passphrases do not match."; return; }
      $("gErr").textContent = "Generating keys, please wait…";
      const r = await createIdentity(p);
      if (!lset(IDK(), r)) { $("gErr").textContent = "The browser blocked saving. Turn off private mode."; return; }
    }
    const r = lget(IDK());
    S.keys = await unlockIdentity(r, p);
    lset(FK, { n: 0, until: 0 });
    const cur = await db.doc("directory/" + S.uid).get();
    const d = cur.exists ? cur.data() : null;
    if (!d || d.encPub !== r.encPub || d.sigPub !== r.sigPub) await db.doc("directory/" + S.uid).set({ v: 1, encPub: r.encPub, sigPub: r.sigPub });
    showChat();
  } catch (e) { if (rec) { const n = ((lget(FK) || {}).n || 0) + 1; lset(FK, { n, until: Date.now() + Math.min(2 ** n, 300) * 1000 }); } $("gErr").textContent = rec ? "Incorrect passphrase." : "Something went wrong. Please try again."; }
  finally { $("gBtn").disabled = false; }
};
$("send").onclick = async () => {
  const t = $("txt").value.trim(); if (!t || !S.sel) return;
  $("send").disabled = true;
  try { await sendMsg(t); $("txt").value = ""; $("txt").style.height = "auto"; } catch (e) { alert("Message not sent. Please try again."); }
  $("send").disabled = false; $("txt").focus();
};
$("txt").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("send").click(); } });
$("txt").addEventListener("input", e => { e.target.style.height = "auto"; e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px"; });
$("back").onclick = () => { $("chat").classList.remove("open"); S.sel = null; renderContacts(); };
$("lockBtn").onclick = lock;
$("verifyBtn").onclick = async () => {
  const fp = await fpOf(S.dir.get(S.sel)), v = lget(VK) || {};
  if (v[S.sel] === fp) delete v[S.sel];
  else if (confirm("Mark as verified only after you have compared the safety number with this person in person, by QR or by call. Continue?")) v[S.sel] = fp;
  else return;
  lset(VK, v); selectPeer(S.sel);
};
$("trust").onclick = async () => {
  const pins = lget(PINK) || {}; pins[S.sel] = await fpOf(S.dir.get(S.sel)); lset(PINK, pins); selectPeer(S.sel);
};
$("bkBtn").onclick = () => {
  const rec = S.uid && lget(IDK());
  $("bkTxt").value = rec ? JSON.stringify(rec) : ""; $("bkErr").textContent = "";
  $("bkTxt").placeholder = "Paste your backup text here to restore"; $("bkDlg").showModal();
};
$("bkClose").onclick = () => $("bkDlg").close();
$("bkRestore").onclick = () => {
  try {
    const o = JSON.parse($("bkTxt").value);
    if (!o.encPub || !o.sigPub || !o.salt || !o.iv || !o.ep) throw 0;
    if (lget(IDK()) && !confirm("The existing key on this device will be replaced by this backup. Continue?")) return;
    lset(IDK(), o); $("bkDlg").close(); lock();
  } catch (e) { $("bkErr").textContent = "Invalid backup text."; }
};

$("cSearch").oninput = () => { renderContacts(); clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 300); }; $("mSearch").oninput = renderMsgs;
$("p1").addEventListener("input", () => {
  const p = $("p1").value, s = strength(p);
  $("meter").hidden = !!lget(IDK()) || !p;
  $("meter").textContent = "Strength: " + (s < 36 ? "Weak" : s < 56 ? "Fair" : "Strong");
});
setInterval(() => { if (S.keys) renderMsgs(); }, 30000);
(async () => {
  try {
    const h = new Uint8Array(await subtle.digest("SHA-256", te.encode(await (await fetch("app.js", { cache: "no-store" })).text())));
    $("codeFp").textContent = "Code fingerprint: " + Array.from(h.slice(0, 6), x => x.toString(16).padStart(2, "0")).join("") + " (compare with a contact)";
  } catch (e) {}
})();
(async () => {
  try {
    ({ db, user } = await window.Backend.init());
    S.uid = user ? await user.id() : null;
  } catch (e) {}
  if (!db || !user || !S.uid) {
    $("gTitle").textContent = "Sign-in required";
    $("gText").textContent = "Sign-in or configuration failed. Check the Supabase URL and key in config.js.";
    return;
  }
  try { const me = await user.me(); $("me").textContent = (me.name || "You") + " · end-to-end encrypted"; } catch (e) {}
  showGate();
})();
