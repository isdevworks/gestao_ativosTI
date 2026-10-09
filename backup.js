// Uso: node backup.js <pasta-de-destino> [quantos-backups-guardar]
// Faz uma cópia consistente do banco (mesmo com o sistema em uso) e apaga os mais antigos.
const fs = require("fs");
const path = require("path");
const { db } = require("./db");

const destino = process.argv[2];
if (!destino) { console.log("Uso: node backup.js <pasta-de-destino> [quantos-guardar]"); process.exit(1); }
const manter = Number(process.argv[3]) || 30;

fs.mkdirSync(destino, { recursive: true });
const d = new Date(), p = (n) => String(n).padStart(2, "0");
const nome = `estoque-${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}.db`;
const arq = path.join(destino, nome);
db.exec(`VACUUM INTO '${arq.replace(/'/g, "''")}'`);

fs.readdirSync(destino).filter((f) => /^estoque-.*\.db$/.test(f)).sort().slice(0, -manter)
  .forEach((f) => fs.unlinkSync(path.join(destino, f)));
console.log("Backup salvo em " + arq);
