// Uso: node criar-usuario.js <usuario> <senha> "Nome Completo" [--admin]
// Se o usuário já existir, troca a senha e o nome.
const { db, hashSenha } = require("./db");
const args = process.argv.slice(2), ehAdmin = args.includes("--admin");
const [usuario, senha, ...nome] = args.filter((a) => a !== "--admin");
if (!usuario || !senha) { console.log('Uso: node criar-usuario.js <usuario> <senha> "Nome Completo"'); process.exit(1); }
if (senha.length < 8) { console.log("A senha precisa ter pelo menos 8 caracteres."); process.exit(1); }
const u = usuario.trim().toLowerCase();
db.prepare("INSERT INTO usuarios(usuario,nome,senha,admin) VALUES(?,?,?,?) ON CONFLICT(usuario) DO UPDATE SET nome=excluded.nome, senha=excluded.senha, admin=CASE WHEN excluded.admin=1 THEN 1 ELSE usuarios.admin END")
  .run(u, nome.join(" ").trim() || u, hashSenha(senha), ehAdmin ? 1 : 0);
db.prepare("DELETE FROM sessoes WHERE usuario_id=(SELECT id FROM usuarios WHERE usuario=?)").run(u);
console.log("Usuário '" + u + "' salvo.");
