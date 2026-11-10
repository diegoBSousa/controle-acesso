# Sistema de Controle de Acessos Seguro e Auditável (PoC do TCC)

## Como rodar
```bash
cd backend
npm install
npm start            # http://127.0.0.1:3000  (API + frontend)
```
Usuários de demonstração: `admin`, `portaria`, `rh` (senha padrão `123456`; troque com a variável `DEMO_PASSWORD`).

Alternativa em contêiner (arquivos `Dockerfile` e `docker-compose.yml`): `docker compose up --build`.
Os testes reportados no TCC foram executados diretamente com Node.js, não no contêiner.

## Como testar (reprodutível)
```bash
cd backend
npm install
npm test             # executa testes/executar_testes.js
```
O executor sobe instâncias próprias do servidor (portas 3100+) com arquivos de dados temporários — **não altera `backend/data.json`** — e grava em `evidencias/execucao_automatizada/`:
`resumo.md` (matriz esperado × obtido), `resultado.json` e `log_bruto.txt` (requisições e respostas).
O cabeçalho do `resumo.md` registra as versões de Node.js e Express usadas. Requer Node 18+; o teste de TLS usa o `openssl`.
As saídas de `evidencias/saidas_brutas/` (curl) e as figuras 1–10 são da primeira rodada de testes.

## Variáveis de ambiente
| Variável | Padrão | Função |
|---|---|---|
| `PORT` / `HOST` | `3000` / `127.0.0.1` | Porta e endereço de escuta |
| `DATA_FILE` | `backend/data.json` | Arquivo de dados |
| `DEMO_PASSWORD` | `123456` | Senha dos usuários de demonstração |
| `SESSION_TTL_MIN` | `30` | Expiração da sessão por inatividade (minutos) |
| `LOGIN_MAX_FAILS` / `LOGIN_WINDOW_MIN` | `5` / `15` | Falhas toleradas por IP+login e janela de bloqueio (HTTP 429) |
| `AUDIT_KEY` | *(vazia)* | Se definida, a cadeia da auditoria usa HMAC-SHA256 (mantenha a chave fora do `data.json` e **não a altere** depois de gerar eventos) |
| `TLS_KEY` / `TLS_CERT` | *(vazias)* | Caminhos de chave e certificado PEM: o servidor passa a atender em HTTPS e envia HSTS |

TLS de teste:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 -subj "/CN=localhost"
TLS_KEY=key.pem TLS_CERT=cert.pem npm start      # https://127.0.0.1:3000
```
Em produção o recomendável é terminar o TLS em um proxy reverso (por exemplo, Nginx) com certificado válido.

## O que mudou no `backend/server.js`
O arquivo `server.js.diff` mostra, linha a linha, todas as alterações em relação ao commit inicial. O frontend não foi alterado.

**Rodada 1 – pontos do orientador**
- Autorização por objeto: `GET /registros`, `/registros/ultimo`, `/registros/abertos`, `/usuarios/:id`, `/carro/:id`, `/veiculo/:id`, `/agendamentos`; pedir dados de outra pessoa retorna 403.
- `GET /usuarios` para colaborador: próprio cadastro + lista mínima (id, nome, tipo) de visitantes e fornecedores.
- Escalada de privilégio: só admin gerencia contas `admin`; RH gerencia qualquer perfil, menos admin; portaria só visitante e fornecedor. `POST /agendar` restrito a admin, RH e colaborador.
- Auditoria com `ip_origem`, `FALHA_LOGIN` e `ACESSO_NEGADO`.

**Rodada 2 – esta entrega**
- **Auditoria com encadeamento de hashes:** cada evento guarda `hash_anterior` e `hash`; `GET /auditoria/verificar` (somente admin) percorre a cadeia e indica o primeiro evento adulterado ou removido. Eventos antigos sem hash são selados na primeira inicialização.
- **Exclusão lógica real:** `DELETE /usuarios/:id` arquiva o cadastro em `usuarios_excluidos` (sem a credencial) e `DELETE /agendamentos/:id` arquiva em `agendamentos_cancelados`; antes os dados eram removidos.
- **Sessão com expiração** por inatividade (`SESSION_TTL_MIN`).
- **Limite de tentativas de login** (HTTP 429, cabeçalho `Retry-After`, evento `LOGIN_BLOQUEADO`).
- **TLS opcional** e cabeçalho HSTS; `X-Content-Type-Options: nosniff`; remoção de `X-Powered-By`.
- `Dockerfile`, `docker-compose.yml`, executor de testes automatizado.

## Limitações que continuam
- Persistência em arquivo JSON (sem transações ACID nem controle de concorrência); sessões e contadores de login em memória (reiniciar o servidor encerra as sessões e zera os contadores).
- A cadeia de hashes **detecta** adulteração, mas não a impede: quem tem acesso ao arquivo pode reescrever a cadeia inteira se não houver `AUDIT_KEY`, e a remoção apenas dos eventos mais recentes só é detectada se o último hash (`ultimo_hash` em `/auditoria/verificar`) for guardado fora do servidor. Ambos os casos aparecem como cenários informativos na matriz de testes.
- O limite de login é por IP+login; não há MFA nem autenticação federada.
- Senha de demonstração padrão (`123456`) deve ser trocada fora de ambiente de teste.
- A cobertura de testes abrange as rotas e perfis da matriz; testes de carga ficam como trabalho futuro.
