const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const crypto = require("crypto");

const db = new DatabaseSync(process.env.DB_PATH || path.join(__dirname, "estoque.db"));
db.exec("PRAGMA journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS pecas    (id TEXT PRIMARY KEY, data TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS config   (k  TEXT PRIMARY KEY, v    TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, senha TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS sessoes  (token TEXT PRIMARY KEY, usuario_id INTEGER NOT NULL, expira INTEGER NOT NULL);
`);

// Migração: bancos antigos ganham a coluna "admin"; o primeiro usuário vira administrador
if (!db.prepare("PRAGMA table_info(usuarios)").all().some((c) => c.name === "admin"))
  db.exec("ALTER TABLE usuarios ADD COLUMN admin INTEGER NOT NULL DEFAULT 0");
db.exec("UPDATE usuarios SET admin=1 WHERE id=(SELECT MIN(id) FROM usuarios) AND NOT EXISTS (SELECT 1 FROM usuarios WHERE admin=1)");

// Senha nunca é guardada em texto: scrypt + salt aleatório
function hashSenha(s) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(s, salt, 64).toString("hex");
}
function confereSenha(s, h) {
  const [salt, k] = h.split(":");
  const a = crypto.scryptSync(s, salt, 64), b = Buffer.from(k, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
module.exports = { db, hashSenha, confereSenha };
