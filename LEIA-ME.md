# O que mudou no backend (server.js)

Arquivo alterado: `backend/server.js`. O `server.js.diff` mostra linha a linha. O frontend não foi alterado.

## 1. Autorização por objeto (ponto do orientador)
- `GET /registros`, `/registros/ultimo`, `/registros/abertos`: admin, rh e portaria veem tudo; os demais só o próprio histórico. Pedir `usuario_id` de outra pessoa retorna **403**.
- `GET /usuarios/:id`, `/carro/:id`, `/veiculo/:id`: só o próprio cadastro (ou admin/rh/portaria).
- `GET /usuarios`: colaborador recebe o próprio cadastro e a lista mínima (id, nome, tipo) de visitantes e fornecedores, necessária para agendar. Sem CPF, e-mail ou foto de terceiros.
- `GET /agendamentos`: colaborador vê os agendamentos pelos quais é responsável; visitante/fornecedor, os próprios.
- `GET /usuarios-agendados-hoje`: restrito a admin, rh e portaria.

## 2. Escalada de privilégio
- Só admin cria, altera ou exclui contas `admin`; rh gerencia qualquer perfil menos admin; portaria só visitante e fornecedor (POST, PUT, toggle-ativo e DELETE de usuários).
- `POST /agendar` restrito a admin, rh e colaborador (a tela da portaria já não oferece agendamento).

## 3. Auditoria
- Novo campo `ip_origem` em todos os eventos.
- Falhas de login passam a gerar `FALHA_LOGIN` (ator desconhecido, com o login tentado).
- Negações de acesso (403) passam a gerar `ACESSO_NEGADO`.

## Não mudou (continua como limitação)
Sessões em memória sem expiração; senha de demonstração `123456`; dados em `data.json`; sem TLS; sem Docker neste zip; log em arquivo JSON alterável por quem acessa o servidor; sem limite de tentativas de login.

## Como rodar
`cd backend`, `npm install`, `npm start` (porta 3000).
