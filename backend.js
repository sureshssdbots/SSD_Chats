// Supabase adapter: app.js ko db/user ka simple interface deta hai.
(() => {
  const cfg = window.SECURECHAT_CONFIG || {};
  const el = id => document.getElementById(id);
  const COL = { from: "sender", to: "recipient" };
  const toMsg = r => ({ from: r.sender, to: r.recipient, ts: Number(r.ts), n: r.n, iv: r.iv, ct: r.ct, wkTo: r.wk_to, wkFrom: r.wk_from, sig: r.sig });
  const toRow = m => ({ sender: m.from, recipient: m.to, ts: m.ts, n: m.n, iv: m.iv, ct: m.ct, wk_to: m.wkTo, wk_from: m.wkFrom, sig: m.sig });
  const toDir = r => ({ v: 1, encPub: r.enc_pub, sigPub: r.sig_pub });
  const MAP = { messages: toMsg, directory: toDir };
  let sb, uid = null, myName = "";
  const docOf = (r, name) => ({ id: r.id, data: () => MAP[name](r) });

  function listen(name, filter, cb) {
    const col = filter ? (COL[filter[0]] || filter[0]) : null;
    const ch = sb.channel(name + "-" + Math.random().toString(36).slice(2))
      .on("postgres_changes", { event: "*", schema: "public", table: name }, p => {
        if (p.eventType === "DELETE") return cb({ docChanges: () => [{ type: "removed", doc: { id: p.old.id, data: () => ({}) } }] });
        if (col && p.new[col] !== filter[1]) return;
        cb({ docChanges: () => [{ type: p.eventType === "INSERT" ? "added" : "modified", doc: docOf(p.new, name) }] });
      }).subscribe();
    (async () => {
      let q = sb.from(name).select("*");
      if (col) q = q.eq(col, filter[1]);
      const { data, error } = await q;
      if (!error) cb({ docChanges: () => data.map(r => ({ type: "added", doc: docOf(r, name) })) });
    })();
    return () => sb.removeChannel(ch);
  }

  const db = {
    collection: name => ({
      where: (f, _op, v) => ({ onSnapshot: cb => listen(name, [f, v], cb) }),
      onSnapshot: cb => listen(name, null, cb),
      add: async m => { const { error } = await sb.from(name).insert(toRow(m)); if (error) throw error; }
    }),
    doc: path => {
      const [name, id] = path.split("/");
      return {
        get: async () => { const { data } = await sb.from(name).select("*").eq("id", id).maybeSingle(); return { exists: !!data, data: () => (data ? MAP[name](data) : null) }; },
        set: async d => { const { error } = await sb.from(name).upsert({ id, enc_pub: d.encPub, sig_pub: d.sigPub }); if (error) throw error; },
        delete: async () => { const { error } = await sb.from(name).delete().eq("id", id); if (error) throw error; }
      };
    }
  };
  const user = {
    id: async () => uid,
    me: async () => ({ name: myName }),
    profiles: async ids => {
      const { data } = await sb.from("profiles").select("id,name,handle").in("id", ids);
      const o = {}; (data || []).forEach(p => { o[p.id] = { name: p.name, handle: p.handle }; }); return o;
    }
  };

  function authScreen() {
    const err = el("aErr"); el("auth").hidden = false; el("gate").hidden = true;
    return new Promise(res => {
      const go = async signup => {
        err.textContent = "";
        const email = el("aEmail").value.trim(), password = el("aPass").value, name = el("aName").value.trim(), handle = el("aHandle").value.trim().toLowerCase().replace(/^@/, "");
        if (!email || password.length < 8) { err.textContent = "Enter an email and a password of 8+ characters."; return; }
        if (signup && (!name || !/^[a-z0-9_]{3,20}$/.test(handle))) { err.textContent = "Enter your name and a username (3-20 letters, numbers or underscore)."; return; }
        if (signup) { const a = await sb.rpc("handle_available", { h: handle }); if (a.error || a.data !== true) { err.textContent = "That username is taken. Try another."; return; } }
        const r = signup
          ? await sb.auth.signUp({ email, password, options: { data: { name, handle } } })
          : await sb.auth.signInWithPassword({ email, password });
        if (r.error) { err.textContent = r.error.message; return; }
        if (!r.data.session) { err.textContent = "A confirmation link was sent to your email. Confirm it, then sign in."; return; }
        el("auth").hidden = true; el("gate").hidden = false; res(r.data.session);
      };
      el("aIn").onclick = () => go(false);
      el("aUp").onclick = () => go(true);
    });
  }

  const hex = async s => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))), x => x.toString(16).padStart(2, "0")).join("");
  // Key transparency: verify the user's hash-chained key history against the current key and our saved chain head.
  async function verifyLog(id, rows, cur) {
    if (!rows.length) return "none";
    let prev = "genesis";
    for (const r of rows) {
      if (r.prev_hash !== prev || r.hash !== await hex(prev + "|" + id + "|" + r.enc_pub + "|" + r.sig_pub)) return "bad";
      prev = r.hash;
    }
    const last = rows[rows.length - 1];
    if (last.enc_pub !== cur.encPub || last.sig_pub !== cur.sigPub) return "bad";
    let heads; try { heads = JSON.parse(localStorage.getItem("securechat-heads") || "{}"); } catch (e) { heads = {}; }
    if (heads[id] && !rows.some(r => r.hash === heads[id])) return "bad";
    heads[id] = last.hash; try { localStorage.setItem("securechat-heads", JSON.stringify(heads)); } catch (e) {}
    return "ok";
  }

  window.Backend = {
    async search(q) {
      const { data } = await sb.from("profiles").select("id,name,handle").like("handle", q + "%").limit(10);
      return data || [];
    },
    async peer(id) {
      const [d, l] = await Promise.all([
        sb.from("directory").select("*").eq("id", id).maybeSingle(),
        sb.from("key_log").select("seq,prev_hash,hash,enc_pub,sig_pub").eq("user_id", id).order("seq", { ascending: true })
      ]);
      if (!d.data) return null;
      const out = toDir(d.data);
      out.tl = await verifyLog(id, l.data || [], out);
      return out;
    },
    async init() {
      if (!cfg.url || cfg.url.includes("YOUR-PROJECT")) throw new Error("config");
      sb = window.supabase.createClient(cfg.url, cfg.anonKey, { auth: { persistSession: true, autoRefreshToken: true } });
      let { data: { session } } = await sb.auth.getSession();
      if (!session) session = await authScreen();
      uid = session.user.id;
      myName = (session.user.user_metadata && session.user.user_metadata.name) || session.user.email.split("@")[0];
      el("outBtn").hidden = false;
      el("outBtn").onclick = async () => { await sb.auth.signOut(); location.reload(); };
      return { db, user };
    }
  };
})();
