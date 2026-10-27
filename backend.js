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
      const { data } = await sb.from("profiles").select("id,name").in("id", ids);
      const o = {}; (data || []).forEach(p => { o[p.id] = { name: p.name }; }); return o;
    }
  };

  function authScreen() {
    const err = el("aErr"); el("auth").hidden = false; el("gate").hidden = true;
    return new Promise(res => {
      const go = async signup => {
        err.textContent = "";
        const email = el("aEmail").value.trim(), password = el("aPass").value, name = el("aName").value.trim();
        if (!email || password.length < 8) { err.textContent = "Email aur 8+ character ka password do."; return; }
        if (signup && !name) { err.textContent = "Sign up ke liye naam bhi do."; return; }
        const r = signup
          ? await sb.auth.signUp({ email, password, options: { data: { name } } })
          : await sb.auth.signInWithPassword({ email, password });
        if (r.error) { err.textContent = r.error.message; return; }
        if (!r.data.session) { err.textContent = "Email par confirmation link gaya hai. Confirm karke sign in karo."; return; }
        el("auth").hidden = true; el("gate").hidden = false; res(r.data.session);
      };
      el("aIn").onclick = () => go(false);
      el("aUp").onclick = () => go(true);
    });
  }

  window.Backend = {
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
