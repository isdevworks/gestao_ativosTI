const { Pool } = require('pg');
const crypto = require('crypto');

// Liga à base de dados na cloud usando o URL do Supabase
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

function hashSenha(senha) {
    return crypto.createHash("sha256").update(senha).digest("hex");
}

function confereSenha(senha, hash) {
    return hashSenha(senha) === hash;
}

module.exports = { pool, hashSenha, confereSenha };