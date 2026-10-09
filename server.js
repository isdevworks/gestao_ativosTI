const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { db, hashSenha, confereSenha } = require("./db");

const PORT = process.env.PORT || 3000;
const DIAS = 30; // quanto tempo o celular continua logado
const PUB = path.join(__dirname, "public");

// Primeiro acesso: cria o administrador a partir de APP_USER / APP_PASS
if (!db.prepare("SELECT 1 FROM usuarios LIMIT 1").get()) {
  const u = (process.env.APP_USER || "ti").toLowerCase(), p = process.env.APP_PASS;
  if (!p) { console.error("Nenhum usuário cadastrado. Defina APP_PASS (e opcional APP_USER) para criar o primeiro."); process.exit(1); }
  db.prepare("INSERT INTO usuarios(usuario,nome,senha,admin) VALUES(?,?,?,1)").run(u, "Administrador", hashSenha(p));
  console.log("Usuário inicial criado: " + u);
}

const sha = (t) => crypto.createHash("sha256").update(t).digest("hex");
const FALSO = hashSenha("x"); // evita revelar se o usuário existe pelo tempo de resposta
const limpar = () => db.prepare("DELETE FROM sessoes WHERE expira<?").run(Date.now());
limpar(); setInterval(limpar, 3600e3);

function lerCookie(req, nome) {
  for (const c of (req.headers.cookie || "").split(";")) {
    const [k, ...v] = c.trim().split("=");
    if (k === nome) return decodeURIComponent(v.join("="));
  }
}
function usuarioDe(req) {
  const t = lerCookie(req, "sid");
  if (!t) return null;
  return db.prepare("SELECT u.id, u.usuario, u.nome, u.admin FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token=? AND s.expira>?").get(sha(t), Date.now()) || null;
}

const tentativas = new Map(); // limite de tentativas de login por IP
const bloqueado = (ip) => {
  const a = (tentativas.get(ip) || []).filter((t) => Date.now() - t < 15 * 60e3);
  tentativas.set(ip, a);
  return a.length >= 10;
};

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // atrás do Caddy/Nginx, para detectar HTTPS
app.use(express.json({ limit: "100kb" }));

// Proteção extra: pedidos de escrita só da mesma origem
app.use((req, res, next) => {
  if (req.method !== "GET" && req.headers.origin) {
    try { if (new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ erro: "origem inválida" }); }
    catch { return res.status(403).json({ erro: "origem inválida" }); }
  }
  next();
});

// Página principal: só com login
app.get(["/", "/index.html"], (req, res) => {
  if (!usuarioDe(req)) return res.redirect("/login.html");
  res.set("Cache-Control", "no-store").sendFile(path.join(PUB, "index.html"));
});
app.use(express.static(PUB, { index: false })); // login, ícones, manifest

app.post("/api/login", (req, res) => {
  if (bloqueado(req.ip)) return res.status(429).json({ erro: "Muitas tentativas. Aguarde 15 minutos." });
  const { usuario, senha } = req.body || {};
  const ok = typeof usuario === "string" && typeof senha === "string";
  const u = ok ? db.prepare("SELECT * FROM usuarios WHERE usuario=?").get(usuario.trim().toLowerCase()) : null;
  const certa = confereSenha(ok ? senha : "", u ? u.senha : FALSO);
  if (!u || !certa) {
    tentativas.get(req.ip).push(Date.now());
    return res.status(401).json({ erro: "Usuário ou senha incorretos." });
  }
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessoes(token,usuario_id,expira) VALUES(?,?,?)").run(sha(token), u.id, Date.now() + DIAS * 864e5);
  res.cookie("sid", token, { httpOnly: true, sameSite: "lax", secure: req.secure, maxAge: DIAS * 864e5, path: "/" });
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const t = lerCookie(req, "sid");
  if (t) db.prepare("DELETE FROM sessoes WHERE token=?").run(sha(t));
  res.clearCookie("sid", { path: "/" });
  res.json({ ok: true });
});

// Tudo abaixo exige login
app.use("/api", (req, res, next) => {
  const u = usuarioDe(req);
  if (!u) return res.status(401).json({ erro: "não autenticado" });
  req.user = u;
  req.tokenHash = sha(lerCookie(req, "sid"));
  next();
});

app.get("/api/me", (req, res) => res.json({ id: req.user.id, usuario: req.user.usuario, nome: req.user.nome, admin: !!req.user.admin }));

const adm = (req, res, next) => (req.user.admin ? next() : res.status(403).json({ erro: "Apenas administradores." }));
const erro = (res, c, m) => res.status(c).json({ erro: m });
const totalAdmins = () => db.prepare("SELECT COUNT(*) c FROM usuarios WHERE admin=1").get().c;
const outrasSessoes = (id, tokenHash) => db.prepare("DELETE FROM sessoes WHERE usuario_id=? AND token<>?").run(id, tokenHash || "");

app.get("/api/usuarios", adm, (_req, res) =>
  res.json(db.prepare("SELECT id, usuario, nome, admin FROM usuarios ORDER BY nome").all().map((u) => ({ ...u, admin: !!u.admin }))));

app.post("/api/usuarios", adm, (req, res) => {
  const { usuario, nome, senha, admin } = req.body || {};
  const u = String(usuario || "").trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(u)) return erro(res, 400, "Usuário: 3 a 32 caracteres, só letras minúsculas, números, ponto, hífen ou _.");
  if (typeof nome !== "string" || !nome.trim()) return erro(res, 400, "Informe o nome.");
  if (typeof senha !== "string" || senha.length < 8) return erro(res, 400, "A senha precisa ter pelo menos 8 caracteres.");
  if (db.prepare("SELECT 1 FROM usuarios WHERE usuario=?").get(u)) return erro(res, 409, "Esse usuário já existe.");
  db.prepare("INSERT INTO usuarios(usuario,nome,senha,admin) VALUES(?,?,?,?)").run(u, nome.trim().slice(0, 80), hashSenha(senha), admin ? 1 : 0);
  res.json({ ok: true });
});

app.put("/api/usuarios/:id", adm, (req, res) => {
  const id = Number(req.params.id);
  const alvo = db.prepare("SELECT * FROM usuarios WHERE id=?").get(id);
  if (!alvo) return erro(res, 404, "Usuário não encontrado.");
  const { nome, senha, admin } = req.body || {};
  if (typeof nome !== "string" || !nome.trim()) return erro(res, 400, "Informe o nome.");
  if (senha && (typeof senha !== "string" || senha.length < 8)) return erro(res, 400, "A senha precisa ter pelo menos 8 caracteres.");
  if (alvo.admin && !admin && totalAdmins() <= 1) return erro(res, 400, "Precisa existir pelo menos um administrador.");
  db.prepare("UPDATE usuarios SET nome=?, admin=? WHERE id=?").run(nome.trim().slice(0, 80), admin ? 1 : 0, id);
  if (senha) {
    db.prepare("UPDATE usuarios SET senha=? WHERE id=?").run(hashSenha(senha), id);
    if (id === req.user.id) outrasSessoes(id, req.tokenHash); else db.prepare("DELETE FROM sessoes WHERE usuario_id=?").run(id);
  }
  res.json({ ok: true });
});

app.delete("/api/usuarios/:id", adm, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return erro(res, 400, "Você não pode excluir o seu próprio usuário.");
  const alvo = db.prepare("SELECT admin FROM usuarios WHERE id=?").get(id);
  if (!alvo) return erro(res, 404, "Usuário não encontrado.");
  if (alvo.admin && totalAdmins() <= 1) return erro(res, 400, "Precisa existir pelo menos um administrador.");
  db.prepare("DELETE FROM sessoes WHERE usuario_id=?").run(id);
  db.prepare("DELETE FROM usuarios WHERE id=?").run(id);
  res.json({ ok: true });
});

app.post("/api/minha-senha", (req, res) => {
  const { atual, nova } = req.body || {};
  const row = db.prepare("SELECT senha FROM usuarios WHERE id=?").get(req.user.id);
  if (typeof atual !== "string" || !row || !confereSenha(atual, row.senha)) return erro(res, 400, "Senha atual incorreta.");
  if (typeof nova !== "string" || nova.length < 8) return erro(res, 400, "A nova senha precisa ter pelo menos 8 caracteres.");
  db.prepare("UPDATE usuarios SET senha=? WHERE id=?").run(hashSenha(nova), req.user.id);
  outrasSessoes(req.user.id, req.tokenHash); // desloga os outros aparelhos
  res.json({ ok: true });
});

const idOk = (id) => /^[\w-]{1,64}$/.test(id);

app.get("/api/dados", (_req, res) => {
  const pecas = db.prepare("SELECT id, data FROM pecas").all().map((r) => ({ ...JSON.parse(r.data), id: r.id }));
  const u = db.prepare("SELECT v FROM config WHERE k='unidades'").get();
  res.json({ pecas, unidades: u ? JSON.parse(u.v) : null });
});

app.put("/api/pecas/:id", (req, res) => {
  const p = req.body;
  if (!idOk(req.params.id) || !p || typeof p.nome !== "string" || !p.nome.trim()) return res.status(400).json({ erro: "dados inválidos" });
  const { id: _ignore, ...data } = p;
  db.prepare("INSERT INTO pecas(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data").run(req.params.id, JSON.stringify(data));
  res.json({ ok: true });
});

app.delete("/api/pecas/:id", (req, res) => {
  if (!idOk(req.params.id)) return res.status(400).json({ erro: "id inválido" });
  db.prepare("DELETE FROM pecas WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.put("/api/unidades", (req, res) => {
  const l = req.body && req.body.lista;
  if (!Array.isArray(l) || l.length < 2 || l.length > 50 || l.some((s) => typeof s !== "string")) return res.status(400).json({ erro: "lista inválida" });
  db.prepare("INSERT INTO config(k,v) VALUES('unidades',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(l));
  res.json({ ok: true });
});

app.listen(PORT, () => console.log("Estoque TI rodando na porta " + PORT));
