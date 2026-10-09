const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { pool, hashSenha, confereSenha } = require("./db");

const PORT = process.env.PORT || 3000;
const DIAS = 30; // quanto tempo o celular continua logado
const PUB = path.join(__dirname, "public");

const sha = (t) => crypto.createHash("sha256").update(t).digest("hex");
const FALSO = hashSenha("x");

// Primeiro acesso: cria o administrador
async function init() {
  try {
    const res = await pool.query("SELECT 1 FROM usuarios LIMIT 1");
    if (res.rowCount === 0) {
      const u = (process.env.APP_USER || "ti").toLowerCase();
      const p = process.env.APP_PASS;
      if (!p) { console.error("Defina APP_PASS para criar o primeiro usuário."); process.exit(1); }
      await pool.query("INSERT INTO usuarios(usuario,nome,senha,admin) VALUES($1,$2,$3,1)", [u, "Administrador", hashSenha(p)]);
      console.log("Usuário inicial criado: " + u);
    }
  } catch(err) { console.error("Erro ao iniciar DB:", err.message); }
}
init();

const limpar = async () => { try { await pool.query("DELETE FROM sessoes WHERE expira < $1", [Date.now()]); } catch(e){} };
limpar(); setInterval(limpar, 3600e3);

function lerCookie(req, nome) {
  for (const c of (req.headers.cookie || "").split(";")) {
    const [k, ...v] = c.trim().split("=");
    if (k === nome) return decodeURIComponent(v.join("="));
  }
}
async function usuarioDe(req) {
  const t = lerCookie(req, "sid");
  if (!t) return null;
  const res = await pool.query("SELECT u.id, u.usuario, u.nome, u.admin FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token=$1 AND s.expira>$2", [sha(t), Date.now()]);
  return res.rows[0] || null;
}

const tentativas = new Map();
const bloqueado = (ip) => {
  const a = (tentativas.get(ip) || []).filter((t) => Date.now() - t < 15 * 60e3);
  tentativas.set(ip, a);
  return a.length >= 10;
};

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));

app.use((req, res, next) => {
  if (req.method !== "GET" && req.headers.origin) {
    try { if (new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ erro: "origem inválida" }); }
    catch { return res.status(403).json({ erro: "origem inválida" }); }
  }
  next();
});

app.get(["/", "/index.html"], async (req, res) => {
  if (!(await usuarioDe(req))) return res.redirect("/login.html");
  res.set("Cache-Control", "no-store").sendFile(path.join(PUB, "index.html"));
});
app.use(express.static(PUB, { index: false }));

app.post("/api/login", async (req, res) => {
  if (bloqueado(req.ip)) return res.status(429).json({ erro: "Muitas tentativas. Aguarde 15 minutos." });
  const { usuario, senha } = req.body || {};
  const ok = typeof usuario === "string" && typeof senha === "string";
  let u = null;
  if (ok) {
      const r = await pool.query("SELECT * FROM usuarios WHERE usuario=$1", [usuario.trim().toLowerCase()]);
      u = r.rows[0];
  }
  const certa = confereSenha(ok ? senha : "", u ? u.senha : FALSO);
  if (!u || !certa) {
    tentativas.get(req.ip).push(Date.now());
    return res.status(401).json({ erro: "Usuário ou senha incorretos." });
  }
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO sessoes(token,usuario_id,expira) VALUES($1,$2,$3)", [sha(token), u.id, Date.now() + DIAS * 864e5]);
  res.cookie("sid", token, { httpOnly: true, sameSite: "lax", secure: req.secure, maxAge: DIAS * 864e5, path: "/" });
  res.json({ ok: true });
});

app.post("/api/logout", async (req, res) => {
  const t = lerCookie(req, "sid");
  if (t) await pool.query("DELETE FROM sessoes WHERE token=$1", [sha(t)]);
  res.clearCookie("sid", { path: "/" });
  res.json({ ok: true });
});

app.use("/api", async (req, res, next) => {
  const u = await usuarioDe(req);
  if (!u) return res.status(401).json({ erro: "não autenticado" });
  req.user = u;
  req.tokenHash = sha(lerCookie(req, "sid"));
  next();
});

app.get("/api/me", (req, res) => res.json({ id: req.user.id, usuario: req.user.usuario, nome: req.user.nome, admin: !!req.user.admin }));

const adm = (req, res, next) => (req.user.admin ? next() : res.status(403).json({ erro: "Apenas administradores." }));
const erro = (res, c, m) => res.status(c).json({ erro: m });
const totalAdmins = async () => { const r = await pool.query("SELECT COUNT(*) c FROM usuarios WHERE admin=1"); return parseInt(r.rows[0].c); };
const outrasSessoes = async (id, tokenHash) => await pool.query("DELETE FROM sessoes WHERE usuario_id=$1 AND token<>$2", [id, tokenHash || ""]);

app.get("/api/usuarios", adm, async (_req, res) => {
  const r = await pool.query("SELECT id, usuario, nome, admin FROM usuarios ORDER BY nome");
  res.json(r.rows.map((u) => ({ ...u, admin: !!u.admin })));
});

app.post("/api/usuarios", adm, async (req, res) => {
  const { usuario, nome, senha, admin } = req.body || {};
  const u = String(usuario || "").trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(u)) return erro(res, 400, "Usuário: 3 a 32 caracteres.");
  if (typeof nome !== "string" || !nome.trim()) return erro(res, 400, "Informe o nome.");
  if (typeof senha !== "string" || senha.length < 8) return erro(res, 400, "A senha precisa ter pelo menos 8 caracteres.");
  const check = await pool.query("SELECT 1 FROM usuarios WHERE usuario=$1", [u]);
  if (check.rowCount > 0) return erro(res, 409, "Esse usuário já existe.");
  await pool.query("INSERT INTO usuarios(usuario,nome,senha,admin) VALUES($1,$2,$3,$4)", [u, nome.trim().slice(0, 80), hashSenha(senha), admin ? 1 : 0]);
  res.json({ ok: true });
});

app.put("/api/usuarios/:id", adm, async (req, res) => {
  const id = Number(req.params.id);
  const r = await pool.query("SELECT * FROM usuarios WHERE id=$1", [id]);
  const alvo = r.rows[0];
  if (!alvo) return erro(res, 404, "Usuário não encontrado.");
  const { nome, senha, admin } = req.body || {};
  const tot = await totalAdmins();
  if (alvo.admin && !admin && tot <= 1) return erro(res, 400, "Precisa existir pelo menos um administrador.");
  await pool.query("UPDATE usuarios SET nome=$1, admin=$2 WHERE id=$3", [nome.trim().slice(0, 80), admin ? 1 : 0, id]);
  if (senha) {
    await pool.query("UPDATE usuarios SET senha=$1 WHERE id=$2", [hashSenha(senha), id]);
    if (id === req.user.id) await outrasSessoes(id, req.tokenHash); else await pool.query("DELETE FROM sessoes WHERE usuario_id=$1", [id]);
  }
  res.json({ ok: true });
});

app.delete("/api/usuarios/:id", adm, async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return erro(res, 400, "Você não pode excluir o seu próprio usuário.");
  const r = await pool.query("SELECT admin FROM usuarios WHERE id=$1", [id]);
  const alvo = r.rows[0];
  const tot = await totalAdmins();
  if (alvo && alvo.admin && tot <= 1) return erro(res, 400, "Precisa existir pelo menos um administrador.");
  await pool.query("DELETE FROM sessoes WHERE usuario_id=$1", [id]);
  await pool.query("DELETE FROM usuarios WHERE id=$1", [id]);
  res.json({ ok: true });
});

app.post("/api/minha-senha", async (req, res) => {
  const { atual, nova } = req.body || {};
  const r = await pool.query("SELECT senha FROM usuarios WHERE id=$1", [req.user.id]);
  const row = r.rows[0];
  if (typeof atual !== "string" || !row || !confereSenha(atual, row.senha)) return erro(res, 400, "Senha atual incorreta.");
  await pool.query("UPDATE usuarios SET senha=$1 WHERE id=$2", [hashSenha(nova), req.user.id]);
  await outrasSessoes(req.user.id, req.tokenHash);
  res.json({ ok: true });
});

const idOk = (id) => /^[\w-]{1,64}$/.test(id);

app.get("/api/dados", async (_req, res) => {
  const r1 = await pool.query("SELECT id, data FROM pecas");
  const pecas = r1.rows.map((r) => ({ ...JSON.parse(r.data), id: r.id }));
  const r2 = await pool.query("SELECT v FROM config WHERE k='unidades'");
  const u = r2.rows[0];
  res.json({ pecas, unidades: u ? JSON.parse(u.v) : null });
});

app.put("/api/pecas/:id", async (req, res) => {
  const p = req.body;
  if (!idOk(req.params.id) || !p || typeof p.nome !== "string" || !p.nome.trim()) return res.status(400).json({ erro: "dados inválidos" });
  const { id: _ignore, ...data } = p;
  await pool.query("INSERT INTO pecas(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data", [req.params.id, JSON.stringify(data)]);
  res.json({ ok: true });
});

app.delete("/api/pecas/:id", async (req, res) => {
  if (!idOk(req.params.id)) return res.status(400).json({ erro: "id inválido" });
  await pool.query("DELETE FROM pecas WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.put("/api/unidades", async (req, res) => {
  const l = req.body && req.body.lista;
  await pool.query("INSERT INTO config(k,v) VALUES('unidades',$1) ON CONFLICT(k) DO UPDATE SET v=EXCLUDED.v", [JSON.stringify(l)]);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log("Estoque TI rodando na porta " + PORT));