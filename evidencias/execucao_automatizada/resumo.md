# Resultado da execução automatizada dos testes

- Data: 2026-11-10T09:54:25.720Z
- Node.js: v26.13.0 | Express: 5.1.0
- Cenários obrigatórios: **45 de 45** com o resultado esperado
- Cenários informativos (limitações conhecidas): 2

| ID | Categoria | Cenário | Perfil | Requisição | Esperado | Obtido | Status |
|---|---|---|---|---|---|---|---|
| T01 | Autenticação e sessão | Requisição sem token | anônimo | `GET /usuarios` | HTTP 401 | HTTP 401 | OK |
| T02 | Autenticação e sessão | Login com senha incorreta | anônimo | `POST /login` | HTTP 401 + evento FALHA_LOGIN | HTTP 401; 1 evento(s) FALHA_LOGIN | OK |
| T03 | Autenticação e sessão | Token invalidado após logout | colaborador | `POST /logout; GET /me` | HTTP 200 e depois 401 | HTTP 200 e depois 401 | OK |
| T04 | Autorização por função (RBAC/BFLA) | Perfil sem permissão cadastra usuário | colaborador | `POST /usuarios` | HTTP 403 | HTTP 403 | OK |
| T05 | Autorização por função (RBAC/BFLA) | Portaria cria usuário admin | portaria | `POST /usuarios (tipo admin)` | HTTP 403 | HTTP 403 | OK |
| T06 | Autorização por função (RBAC/BFLA) | RH altera a conta do administrador | rh | `PUT /usuarios/1` | HTTP 403 | HTTP 403 | OK |
| T07 | Autorização por função (RBAC/BFLA) | Portaria cria agendamento | portaria | `POST /agendar` | HTTP 403 | HTTP 403 | OK |
| T08 | Autorização por função (RBAC/BFLA) | Portaria exclui conta de RH | portaria | `DELETE /usuarios/3` | HTTP 403 | HTTP 403 | OK |
| T09 | Autorização por função (RBAC/BFLA) | Colaborador altera cadastro de outro | colaborador | `PUT /usuarios/7` | HTTP 403 | HTTP 403 | OK |
| T10 | Autorização por função (RBAC/BFLA) | Colaborador exclui outro usuário | colaborador | `DELETE /usuarios/7` | HTTP 403 | HTTP 403 | OK |
| T11 | Autorização por função (RBAC/BFLA) | Visitante cria agendamento | visitante | `POST /agendar` | HTTP 403 | HTTP 403 | OK |
| T12 | Autorização por objeto (BOLA) | Colaborador A lê histórico do colaborador B | colaborador | `GET /registros?usuario_id=7` | HTTP 403 | HTTP 403 | OK |
| T13 | Autorização por objeto (BOLA) | Colaborador A lê cadastro do colaborador B | colaborador | `GET /usuarios/7` | HTTP 403 | HTTP 403 | OK |
| T14 | Autorização por objeto (BOLA) | Colaborador lista agendamentos | colaborador | `GET /agendamentos` | HTTP 200, apenas os próprios | HTTP 200; 1 item(ns), todos próprios: true | OK |
| T15 | Autorização por objeto (BOLA) | Listagem de usuários para colaborador | colaborador | `GET /usuarios` | HTTP 200; próprio cadastro + lista mínima, sem CPF/e-mail de terceiros | HTTP 200; 5 item(ns); sem CPF/e-mail de terceiros: true | OK |
| T16 | Autorização por objeto (BOLA) | Colaborador cancela agendamento de outro responsável | colaborador | `DELETE /agendamentos/1` | HTTP 403 | HTTP 403 | OK |
| T17 | Autorização por objeto (BOLA) | Visitante lista agendamentos | visitante | `GET /agendamentos` | HTTP 200, apenas os próprios | HTTP 200; 1 item(ns), todos próprios: true | OK |
| T18 | Autorização por objeto (BOLA) | Visitante lê cadastro de colaborador | visitante | `GET /usuarios/6` | HTTP 403 | HTTP 403 | OK |
| T19 | Autorização por objeto (BOLA) | Visitante lê histórico de colaborador | visitante | `GET /registros?usuario_id=6` | HTTP 403 | HTTP 403 | OK |
| T20 | Autorização por objeto (BOLA) | Fornecedor lista usuários | fornecedor | `GET /usuarios` | HTTP 200, somente o próprio cadastro | HTTP 200; 1 item(ns) | OK |
| T21 | Regras de negócio e integridade de estado | Entrada válida | portaria | `POST /registros (entrada)` | HTTP 201 | HTTP 201 | OK |
| T22 | Regras de negócio e integridade de estado | Entrada duplicada | portaria | `POST /registros (entrada)` | HTTP 409 | HTTP 409 | OK |
| T23 | Regras de negócio e integridade de estado | Saída sem entrada ativa | portaria | `POST /registros (saída)` | HTTP 409 | HTTP 409 | OK |
| T24 | Regras de negócio e integridade de estado | Saída com entrada ativa | portaria | `POST /registros (saída)` | HTTP 201 | HTTP 201 | OK |
| T25 | Regras de negócio e integridade de estado | Cadastro com CPF duplicado | admin | `POST /usuarios` | HTTP 409 | HTTP 409 | OK |
| T26 | Regras de negócio e integridade de estado | Responsável forjado no corpo da requisição | colaborador | `POST /agendar (responsavel_id=1)` | HTTP 201; responsável = usuário da sessão | HTTP 201; responsavel_id=6 | OK |
| T27 | Regras de negócio e integridade de estado | Exclusão lógica de usuário preserva histórico | admin | `DELETE /usuarios/10` | HTTP 200; cadastro arquivado (sem credencial); registros e auditoria mantidos | HTTP 200; 2 registro(s) mantido(s); 1 evento(s) EXCLUSAO_USUARIO; arquivado: true; sem senha_hash: true | OK |
| T28 | Regras de negócio e integridade de estado | Cancelamento de agendamento é arquivado | admin | `DELETE /agendamentos/2` | HTTP 200; cancelamento arquivado | HTTP 200; arquivado: true | OK |
| T29 | Auditoria e integridade | Consulta da trilha de auditoria | admin | `GET /auditoria` | HTTP 200; eventos com ator, IP e hash | HTTP 200; 39 evento(s); todos com ip_origem e hash: true | OK |
| T30 | Auditoria e integridade | Negações de acesso geram evento | admin | `GET /auditoria?acao=ACESSO_NEGADO` | ao menos 1 evento ACESSO_NEGADO | 12 evento(s) | OK |
| T31 | Auditoria e integridade | Exclusão de registro de acesso | admin | `DELETE /registros/1` | HTTP 405 | HTTP 405 | OK |
| T32 | Auditoria e integridade | Exclusão da trilha de auditoria | admin | `DELETE /auditoria` | HTTP 405 | HTTP 405 | OK |
| T33 | Auditoria e integridade | Exclusão de evento de auditoria | admin | `DELETE /auditoria/1` | HTTP 405 | HTTP 405 | OK |
| T34 | Auditoria e integridade | Exclusão da trilha por perfil não admin | portaria | `DELETE /auditoria` | HTTP 403 | HTTP 403 | OK |
| T35 | Auditoria e integridade | PUT na trilha de auditoria | admin | `PUT /auditoria` | HTTP 404 (sem rota) | HTTP 404 | OK |
| T36 | Auditoria e integridade | PATCH na trilha de auditoria | admin | `PATCH /auditoria` | HTTP 404 (sem rota) | HTTP 404 | OK |
| T37 | Auditoria e integridade | POST na trilha de auditoria | admin | `POST /auditoria` | HTTP 404 (sem rota) | HTTP 404 | OK |
| T38 | Auditoria e integridade | Verificação da cadeia de hashes (log íntegro) | admin | `GET /auditoria/verificar` | integra = true | HTTP 200; integra = true; 40 eventos; SHA-256 | OK |
| T39 | Auditoria e integridade | Verificação da cadeia por perfil não admin | colaborador | `GET /auditoria/verificar` | HTTP 403 | HTTP 403 | OK |
| T40 | Auditoria e integridade | Verificação da cadeia sem token | anônimo | `GET /auditoria/verificar` | HTTP 401 | HTTP 401 | OK |
| T41 | Autenticação e sessão | Bloqueio após 5 falhas de login consecutivas | anônimo | `POST /login ×6` | 5×HTTP 401, depois HTTP 429 + Retry-After + evento LOGIN_BLOQUEADO | 401,401,401,401,401, depois HTTP 429; Retry-After: 900; 1 evento(s) LOGIN_BLOQUEADO | OK |
| T42 | Auditoria e integridade | Evento de auditoria alterado direto no arquivo | atacante com acesso ao arquivo | `edição de data.json + GET /auditoria/verificar` | integra = false; primeiro evento quebrado = 25 | integra = false; primeiro_quebrado = 25; motivo: conteúdo do evento alterado | OK |
| T43 | Auditoria e integridade | Evento de auditoria removido do meio da trilha | atacante com acesso ao arquivo | `remoção em data.json + GET /auditoria/verificar` | integra = false; primeiro evento quebrado = 26 | integra = false; primeiro_quebrado = 26; motivo: encadeamento rompido (evento removido, inserido ou reordenado) | OK |
| T44 | Auditoria e integridade | LIMITAÇÃO: remoção apenas do evento mais recente | atacante com acesso ao arquivo | `remoção do último evento + GET /auditoria/verificar` | não detectada (sem âncora externa do último hash) | integra = true (truncar o fim da cadeia não é detectável sem guardar o último hash fora do servidor) | INFO |
| T45 | Auditoria e integridade | LIMITAÇÃO: cadeia reescrita sem AUDIT_KEY | atacante com acesso ao arquivo | `alteração + recálculo SHA-256 da cadeia inteira` | não detectada (SHA-256 puro pode ser recalculado por quem tem o arquivo) | integra = true (sem chave secreta, a cadeia pode ser refeita) | INFO |
| T46 | Auditoria e integridade | Cadeia reescrita sem conhecer a AUDIT_KEY (HMAC) | atacante com acesso ao arquivo | `alteração + recálculo SHA-256 + GET /auditoria/verificar` | integra = false (HMAC exige a chave, que não está no arquivo) | integra = false; servidor iniciado com AUDIT_KEY; motivo: conteúdo do evento alterado | OK |
| T47 | Autenticação e sessão | Expiração de sessão por inatividade | admin | `GET /me antes e depois do TTL` | HTTP 200 e depois HTTP 401 | HTTP 200 e depois 401 | OK |
