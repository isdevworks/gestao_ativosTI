# Estoque de TI – Madeireira Brotas

Node.js 22.5+ (Express + SQLite embutido). Login com sessão e senhas criptografadas.. Os dados ficam no arquivo `estoque.db`.

## Rodar
    npm install
    APP_USER=ti APP_PASS='uma-senha-forte' npm start
Acesse http://localhost:3000

## Produção
- Defina `APP_PASS` (obrigatório) e, se quiser, `APP_USER`, `PORT`, `DB_PATH`.
- Publique atrás de HTTPS (Nginx/Caddy ou o próprio painel do provedor). A senha trafega em Basic Auth.
- Mantenha o `estoque.db` em disco persistente e faça backup (copiar o arquivo).
- Para manter ligado: `pm2 start server.js --name estoque-ti`.

## Login
- No primeiro start, o usuário inicial é criado com `APP_USER` (padrão `ti`) e `APP_PASS`. Depois disso `APP_PASS` não é mais necessário.
- Criar outro usuário ou trocar senha: `node criar-usuario.js maria SenhaForte123 "Maria Silva"`
- Sessão dura 30 dias no celular; o botão "Sair" encerra.
- Em produção use HTTPS (o cookie de login passa a ser marcado como Secure automaticamente).

Desenvolvido por Ícaro Souza · IsDevWorks

## Usuários (dentro do app)
- O primeiro usuário é administrador e vê o botão **Usuários** no topo: cadastra, edita, troca senha, dá ou tira permissão de administrador e exclui.
- Qualquer usuário troca a própria senha em **Alterar minha senha** (rodapé).
- Pelo terminal: `node criar-usuario.js maria SenhaForte123 "Maria Silva" --admin` (o `--admin` é opcional).
