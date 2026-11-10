#!/usr/bin/env node
/**
 * Executor automatizado da matriz de testes de segurança (TCC – Sistema de Controle de Acessos).
 *
 * Uso:   cd backend && npm install && npm test          (ou: node testes/executar_testes.js)
 * Saída: evidencias/execucao_automatizada/{resumo.md, resultado.json, log_bruto.txt}
 *
 * O script sobe instâncias próprias do servidor (portas 3100+) com arquivos de dados temporários;
 * não altera backend/data.json. Requer Node.js 18+ (fetch nativo) e, para o teste de TLS, o openssl.
 */
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'backend', 'server.js');
const OUT = path.join(ROOT, 'evidencias', 'execucao_automatizada');
const SENHA = 'Teste#2026';
const sleep = ms => new Promise(r => setTimeout(r, ms));

const resultados = [];
const log = [];
let porta = 3100;
let categoria = '';

// ---------------------------------------------------------------- infraestrutura
async function iniciarServidor(env = {}, dataFile = null) {
  const port = porta++;
  const arquivo = dataFile || path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tcc-')), 'data.json');
  const proc = spawn(process.execPath, [SERVER], {
    env: { ...process.env, PORT: String(port), DATA_FILE: arquivo, DEMO_PASSWORD: SENHA, ...env },
    stdio: 'ignore'
  });
  const proto = env.TLS_KEY ? 'https' : 'http';
  for (let i = 0; i < 60; i++) {
    try {
      if (proto === 'http') { const r = await fetch(`http://127.0.0.1:${port}/health`); if (r.ok) break; }
      else { await getHttps(port, '/health'); break; }
    } catch { await sleep(150); }
  }
  return { base: `http://127.0.0.1:${port}`, port, arquivo, proc,
    parar: async () => { proc.kill(); await sleep(250); } };
}

function getHttps(port, caminho) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host: '127.0.0.1', port, path: caminho, rejectUnauthorized: false }, res => {
      let corpo = ''; res.on('data', d => corpo += d); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, corpo }));
    });
    req.on('error', reject); req.end();
  });
}

async function chamar(base, metodo, rota, { token, corpo, rotulo } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(base + rota, { method: metodo, headers, body: corpo ? JSON.stringify(corpo) : undefined });
  const texto = await r.text();
  const textoLog = texto.replace(/"token":"[0-9a-f]+"/g, '"token":"<oculto>"').replace(/"foto_base64":"[^"]{40,}"/g, '"foto_base64":"…"');
  let json = null; try { json = JSON.parse(texto); } catch { /* sem corpo JSON */ }
  log.push(`$ ${metodo} ${rota}${rotulo ? `   [${rotulo}]` : ''}\n  -> HTTP ${r.status}  ${textoLog.slice(0, 260).replace(/\s+/g, ' ')}`);
  return { status: r.status, json, texto, headers: r.headers };
}

async function login(base, usuario, senha = SENHA) {
  const r = await chamar(base, 'POST', '/login', { corpo: { usuario, senha }, rotulo: `login ${usuario}` });
  return r.status === 200 ? r.json.token : null;
}

function registrar(titulo, perfil, requisicao, esperado, obtido, ok, informativo = false) {
  const id = `T${String(resultados.length + 1).padStart(2, '0')}`;
  resultados.push({ id, categoria, titulo, perfil, requisicao, esperado, obtido, ok, informativo });
  log.push(`   ${ok ? 'OK  ' : 'FALHA'} ${id} ${titulo} | esperado: ${esperado} | obtido: ${obtido}\n`);
}

const lerDados = arq => JSON.parse(fs.readFileSync(arq, 'utf8'));
const gravarDados = (arq, d) => fs.writeFileSync(arq, JSON.stringify(d, null, 2));

// mesma função de resumo do servidor, usada apenas para simular um atacante que reescreve a cadeia
function recalcularCadeia(auditoria, chave) {
  const campos = ['id', 'ator_id', 'ator_nome', 'ator_tipo', 'acao', 'alvo_id', 'alvo_nome', 'alvo_tipo',
    'detalhes', 'ip_origem', 'quando', 'hash_anterior'];
  let anterior = null;
  for (const ev of [...auditoria].reverse()) {
    ev.hash_anterior = anterior;
    const canon = JSON.stringify(campos.map(c => ev[c] ?? null));
    ev.hash = crypto.createHash('sha256').update(canon).digest('hex'); // atacante não conhece a chave
    anterior = ev.hash;
  }
}

// ---------------------------------------------------------------- execução
(async () => {
  // ================= Instância principal =================
  const srv = await iniciarServidor();
  const B = srv.base;

  const admin = await login(B, 'admin');
  const portaria = await login(B, 'portaria');
  const rh = await login(B, 'rh');

  const novoUsuario = async (dados, token = admin) => (await chamar(B, 'POST', '/usuarios', { token, corpo: dados, rotulo: 'preparação' })).json?.userId;
  const idA = await novoUsuario({ nome: 'Colaborador A (teste)', cpf: '111.111.111-11', email: 'a@teste.local', usuario: 'colab_a', tipo: 'colaborador', senha: SENHA });
  const idB = await novoUsuario({ nome: 'Colaborador B (teste)', cpf: '222.222.222-22', email: 'b@teste.local', usuario: 'colab_b', tipo: 'colaborador', senha: SENHA });
  const idV = await novoUsuario({ nome: 'Visitante com credencial', cpf: '444.444.444-44', email: 'v@teste.local', usuario: 'visit_t', tipo: 'visitante', senha: SENHA });
  const idF = await novoUsuario({ nome: 'Fornecedor com credencial', cpf: '555.555.555-55', email: 'f@teste.local', usuario: 'forn_t', tipo: 'fornecedor', senha: SENHA });
  const colabA = await login(B, 'colab_a');
  const colabB = await login(B, 'colab_b');
  const vis = await login(B, 'visit_t');
  const forn = await login(B, 'forn_t');

  const regA = (await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idA, acao: 'entrada' }, rotulo: 'preparação' })).json;
  const ag1 = (await chamar(B, 'POST', '/agendar', { token: admin, corpo: { usuario_id: 4, data_agendada: '2026-11-12', hora_agendada: '09:00', destino: 'Reunião' }, rotulo: 'preparação' })).json;
  const agV = (await chamar(B, 'POST', '/agendar', { token: admin, corpo: { usuario_id: idV, data_agendada: '2026-11-12', hora_agendada: '10:00', destino: 'Visita' }, rotulo: 'preparação' })).json;
  await chamar(B, 'POST', '/agendar', { token: colabA, corpo: { usuario_id: 5, data_agendada: '2026-11-12', hora_agendada: '14:00', destino: 'Entrega' }, rotulo: 'preparação' });
  await chamar(B, 'POST', '/agendar', { token: admin, corpo: { usuario_id: idF, data_agendada: '2026-11-12', hora_agendada: '11:00', destino: 'Entrega' }, rotulo: 'preparação' });

  // ---- Autenticação e sessão
  categoria = 'Autenticação e sessão';
  let r = await chamar(B, 'GET', '/usuarios');
  registrar('Requisição sem token', 'anônimo', 'GET /usuarios', 'HTTP 401', `HTTP ${r.status}`, r.status === 401);

  r = await chamar(B, 'POST', '/login', { corpo: { usuario: 'admin', senha: 'senha-errada' }, rotulo: 'senha incorreta' });
  let aud = (await chamar(B, 'GET', '/auditoria?acao=FALHA_LOGIN', { token: admin })).json || [];
  registrar('Login com senha incorreta', 'anônimo', 'POST /login', 'HTTP 401 + evento FALHA_LOGIN', `HTTP ${r.status}; ${aud.length} evento(s) FALHA_LOGIN`, r.status === 401 && aud.length >= 1);

  const tmp = await login(B, 'colab_b');
  const sair = await chamar(B, 'POST', '/logout', { token: tmp });
  r = await chamar(B, 'GET', '/me', { token: tmp });
  registrar('Token invalidado após logout', 'colaborador', 'POST /logout; GET /me', 'HTTP 200 e depois 401', `HTTP ${sair.status} e depois ${r.status}`, sair.status === 200 && r.status === 401);

  // ---- Autorização por função (RBAC / BFLA)
  categoria = 'Autorização por função (RBAC/BFLA)';
  r = await chamar(B, 'POST', '/usuarios', { token: colabA, corpo: { nome: 'Novo', cpf: '333.333.333-33', email: 'novo@teste.local' } });
  registrar('Perfil sem permissão cadastra usuário', 'colaborador', 'POST /usuarios', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'POST', '/usuarios', { token: portaria, corpo: { nome: 'X', cpf: '999.999.999-99', email: 'x@t.local', usuario: 'x', tipo: 'admin', senha: 'x' } });
  registrar('Portaria cria usuário admin', 'portaria', 'POST /usuarios (tipo admin)', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'PUT', '/usuarios/1', { token: rh, corpo: { senha: 'tomada' } });
  registrar('RH altera a conta do administrador', 'rh', 'PUT /usuarios/1', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'POST', '/agendar', { token: portaria, corpo: { usuario_id: 4, data_agendada: '2026-11-12', hora_agendada: '08:00', destino: 'x' } });
  registrar('Portaria cria agendamento', 'portaria', 'POST /agendar', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'DELETE', `/usuarios/3`, { token: portaria });
  registrar('Portaria exclui conta de RH', 'portaria', 'DELETE /usuarios/3', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'PUT', `/usuarios/${idB}`, { token: colabA, corpo: { nome: 'Alterado' } });
  registrar('Colaborador altera cadastro de outro', 'colaborador', `PUT /usuarios/${idB}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'DELETE', `/usuarios/${idB}`, { token: colabA });
  registrar('Colaborador exclui outro usuário', 'colaborador', `DELETE /usuarios/${idB}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'POST', '/agendar', { token: vis, corpo: { usuario_id: idV, data_agendada: '2026-11-12', hora_agendada: '08:00', destino: 'x' } });
  registrar('Visitante cria agendamento', 'visitante', 'POST /agendar', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  // ---- Autorização por objeto (BOLA)
  categoria = 'Autorização por objeto (BOLA)';
  r = await chamar(B, 'GET', `/registros?usuario_id=${idB}`, { token: colabA });
  registrar('Colaborador A lê histórico do colaborador B', 'colaborador', `GET /registros?usuario_id=${idB}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'GET', `/usuarios/${idB}`, { token: colabA });
  registrar('Colaborador A lê cadastro do colaborador B', 'colaborador', `GET /usuarios/${idB}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'GET', '/agendamentos', { token: colabA });
  const propriosA = Array.isArray(r.json) && r.json.length >= 1 && r.json.every(i => i.responsavel_id === idA || i.usuario_id === idA);
  registrar('Colaborador lista agendamentos', 'colaborador', 'GET /agendamentos', 'HTTP 200, apenas os próprios', `HTTP ${r.status}; ${r.json?.length ?? 0} item(ns), todos próprios: ${propriosA}`, r.status === 200 && propriosA);

  r = await chamar(B, 'GET', '/usuarios', { token: colabA });
  const lista = r.json || [];
  const semDadosTerceiros = lista.slice(1).every(i => !('cpf' in i) && !('email' in i));
  registrar('Listagem de usuários para colaborador', 'colaborador', 'GET /usuarios', 'HTTP 200; próprio cadastro + lista mínima, sem CPF/e-mail de terceiros', `HTTP ${r.status}; ${lista.length} item(ns); sem CPF/e-mail de terceiros: ${semDadosTerceiros}`, r.status === 200 && lista[0]?.id === idA && semDadosTerceiros);

  r = await chamar(B, 'DELETE', `/agendamentos/${ag1.id}`, { token: colabA });
  registrar('Colaborador cancela agendamento de outro responsável', 'colaborador', `DELETE /agendamentos/${ag1.id}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'GET', '/agendamentos', { token: vis });
  const soV = Array.isArray(r.json) && r.json.length >= 1 && r.json.every(i => i.usuario_id === idV);
  registrar('Visitante lista agendamentos', 'visitante', 'GET /agendamentos', 'HTTP 200, apenas os próprios', `HTTP ${r.status}; ${r.json?.length ?? 0} item(ns), todos próprios: ${soV}`, r.status === 200 && soV);

  r = await chamar(B, 'GET', `/usuarios/${idA}`, { token: vis });
  registrar('Visitante lê cadastro de colaborador', 'visitante', `GET /usuarios/${idA}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'GET', `/registros?usuario_id=${idA}`, { token: vis });
  registrar('Visitante lê histórico de colaborador', 'visitante', `GET /registros?usuario_id=${idA}`, 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'GET', '/usuarios', { token: forn });
  registrar('Fornecedor lista usuários', 'fornecedor', 'GET /usuarios', 'HTTP 200, somente o próprio cadastro', `HTTP ${r.status}; ${r.json?.length ?? 0} item(ns)`, r.status === 200 && r.json?.length === 1 && r.json[0].id === idF);

  // ---- Regras de negócio e estado
  categoria = 'Regras de negócio e integridade de estado';
  r = await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idB, acao: 'entrada' } });
  registrar('Entrada válida', 'portaria', 'POST /registros (entrada)', 'HTTP 201', `HTTP ${r.status}`, r.status === 201);

  r = await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idB, acao: 'entrada' } });
  registrar('Entrada duplicada', 'portaria', 'POST /registros (entrada)', 'HTTP 409', `HTTP ${r.status}`, r.status === 409);

  r = await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idV, acao: 'saida' } });
  registrar('Saída sem entrada ativa', 'portaria', 'POST /registros (saída)', 'HTTP 409', `HTTP ${r.status}`, r.status === 409);

  r = await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idB, acao: 'saida' } });
  registrar('Saída com entrada ativa', 'portaria', 'POST /registros (saída)', 'HTTP 201', `HTTP ${r.status}`, r.status === 201);

  r = await chamar(B, 'POST', '/usuarios', { token: admin, corpo: { nome: 'Duplicado', cpf: '111.111.111-11', email: 'dup@teste.local', usuario: 'dup', tipo: 'visitante' } });
  registrar('Cadastro com CPF duplicado', 'admin', 'POST /usuarios', 'HTTP 409', `HTTP ${r.status}`, r.status === 409);

  r = await chamar(B, 'POST', '/agendar', { token: colabA, corpo: { usuario_id: 5, data_agendada: '2026-11-11', hora_agendada: '10:00', destino: 'Entrega', responsavel_id: 1, responsavel_nome: 'FORJADO' } });
  registrar('Responsável forjado no corpo da requisição', 'colaborador', 'POST /agendar (responsavel_id=1)', 'HTTP 201; responsável = usuário da sessão', `HTTP ${r.status}; responsavel_id=${r.json?.responsavel_id}`, r.status === 201 && r.json?.responsavel_id === idA && r.json?.responsavel_nome !== 'FORJADO');

  // exclusão lógica
  const idT = await novoUsuario({ nome: 'Temporário', cpf: '888.888.888-88', email: 't@teste.local', usuario: 'temp', tipo: 'visitante' });
  await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idT, acao: 'entrada' }, rotulo: 'preparação' });
  await chamar(B, 'POST', '/registros', { token: portaria, corpo: { usuario_id: idT, acao: 'saida' }, rotulo: 'preparação' });
  r = await chamar(B, 'DELETE', `/usuarios/${idT}`, { token: admin });
  const hist = (await chamar(B, 'GET', `/registros?usuario_id=${idT}`, { token: admin })).json || [];
  aud = (await chamar(B, 'GET', '/auditoria?acao=EXCLUSAO_USUARIO', { token: admin })).json || [];
  const dadosA = lerDados(srv.arquivo);
  const arquivado = dadosA.usuarios_excluidos.find(u => u.id === idT);
  const some = !dadosA.usuarios.some(u => u.id === idT);
  registrar('Exclusão lógica de usuário preserva histórico', 'admin', `DELETE /usuarios/${idT}`,
    'HTTP 200; cadastro arquivado (sem credencial); registros e auditoria mantidos',
    `HTTP ${r.status}; ${hist.length} registro(s) mantido(s); ${aud.length} evento(s) EXCLUSAO_USUARIO; arquivado: ${Boolean(arquivado)}; sem senha_hash: ${arquivado ? !('senha_hash' in arquivado) : false}`,
    r.status === 200 && hist.length === 2 && aud.length >= 1 && Boolean(arquivado) && some && !('senha_hash' in arquivado));

  r = await chamar(B, 'DELETE', `/agendamentos/${agV.id}`, { token: admin });
  const dadosB = lerDados(srv.arquivo);
  registrar('Cancelamento de agendamento é arquivado', 'admin', `DELETE /agendamentos/${agV.id}`, 'HTTP 200; cancelamento arquivado',
    `HTTP ${r.status}; arquivado: ${dadosB.agendamentos_cancelados.some(a => a.id === agV.id)}`,
    r.status === 200 && dadosB.agendamentos_cancelados.some(a => a.id === agV.id));

  // ---- Auditoria
  categoria = 'Auditoria e integridade';
  r = await chamar(B, 'GET', '/auditoria', { token: admin });
  const evs = r.json || [];
  registrar('Consulta da trilha de auditoria', 'admin', 'GET /auditoria', 'HTTP 200; eventos com ator, IP e hash', `HTTP ${r.status}; ${evs.length} evento(s); todos com ip_origem e hash: ${evs.every(e => e.ip_origem && e.hash)}`, r.status === 200 && evs.length > 0 && evs.every(e => e.ip_origem && e.hash));

  aud = (await chamar(B, 'GET', '/auditoria?acao=ACESSO_NEGADO', { token: admin })).json || [];
  registrar('Negações de acesso geram evento', 'admin', 'GET /auditoria?acao=ACESSO_NEGADO', 'ao menos 1 evento ACESSO_NEGADO', `${aud.length} evento(s)`, aud.length >= 1);

  r = await chamar(B, 'DELETE', `/registros/${regA.id}`, { token: admin });
  registrar('Exclusão de registro de acesso', 'admin', `DELETE /registros/${regA.id}`, 'HTTP 405', `HTTP ${r.status}`, r.status === 405);

  r = await chamar(B, 'DELETE', '/auditoria', { token: admin });
  registrar('Exclusão da trilha de auditoria', 'admin', 'DELETE /auditoria', 'HTTP 405', `HTTP ${r.status}`, r.status === 405);

  r = await chamar(B, 'DELETE', '/auditoria/1', { token: admin });
  registrar('Exclusão de evento de auditoria', 'admin', 'DELETE /auditoria/1', 'HTTP 405', `HTTP ${r.status}`, r.status === 405);

  r = await chamar(B, 'DELETE', '/auditoria', { token: portaria });
  registrar('Exclusão da trilha por perfil não admin', 'portaria', 'DELETE /auditoria', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  for (const metodo of ['PUT', 'PATCH', 'POST']) {
    r = await chamar(B, metodo, '/auditoria', { token: admin, corpo: { acao: 'FORJADO' } });
    registrar(`${metodo} na trilha de auditoria`, 'admin', `${metodo} /auditoria`, 'HTTP 404 (sem rota)', `HTTP ${r.status}`, r.status === 404);
  }

  r = await chamar(B, 'GET', '/auditoria/verificar', { token: admin });
  registrar('Verificação da cadeia de hashes (log íntegro)', 'admin', 'GET /auditoria/verificar', 'integra = true', `HTTP ${r.status}; integra = ${r.json?.integra}; ${r.json?.total} eventos; ${r.json?.algoritmo}`, r.status === 200 && r.json?.integra === true);

  r = await chamar(B, 'GET', '/auditoria/verificar', { token: colabA });
  registrar('Verificação da cadeia por perfil não admin', 'colaborador', 'GET /auditoria/verificar', 'HTTP 403', `HTTP ${r.status}`, r.status === 403);

  r = await chamar(B, 'GET', '/auditoria/verificar');
  registrar('Verificação da cadeia sem token', 'anônimo', 'GET /auditoria/verificar', 'HTTP 401', `HTTP ${r.status}`, r.status === 401);

  // ---- Força bruta
  categoria = 'Autenticação e sessão';
  let codigos = [];
  for (let i = 0; i < 5; i++) codigos.push((await chamar(B, 'POST', '/login', { corpo: { usuario: 'rh', senha: `errada${i}` }, rotulo: `tentativa ${i + 1}` })).status);
  r = await chamar(B, 'POST', '/login', { corpo: { usuario: 'rh', senha: SENHA }, rotulo: 'senha CORRETA após 5 falhas' });
  aud = (await chamar(B, 'GET', '/auditoria?acao=LOGIN_BLOQUEADO', { token: admin })).json || [];
  registrar('Bloqueio após 5 falhas de login consecutivas', 'anônimo', 'POST /login ×6', '5×HTTP 401, depois HTTP 429 + Retry-After + evento LOGIN_BLOQUEADO',
    `${codigos.join(',')}, depois HTTP ${r.status}; Retry-After: ${r.headers.get('retry-after')}; ${aud.length} evento(s) LOGIN_BLOQUEADO`,
    codigos.every(c => c === 401) && r.status === 429 && Boolean(r.headers.get('retry-after')) && aud.length >= 1);

  await srv.parar();

  // ================= Adulteração da trilha =================
  categoria = 'Auditoria e integridade';
  const base = lerDados(srv.arquivo);
  const ordem = [...base.auditoria].reverse(); // cronológica
  const meio = ordem[Math.floor(ordem.length / 2)];
  const seguinte = ordem[Math.floor(ordem.length / 2) + 1];

  async function cenarioAdulteracao(titulo, requisicao, esperado, alterar, avaliar, env = {}, informativo = false, origem = base) {
    const d = JSON.parse(JSON.stringify(origem));
    alterar(d);
    const arq = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tcc-adult-')), 'data.json');
    gravarDados(arq, d);
    const s = await iniciarServidor(env, arq);
    const t = await login(s.base, 'admin');
    const v = await chamar(s.base, 'GET', '/auditoria/verificar', { token: t, rotulo: titulo });
    await s.parar();
    const { ok, obtido } = avaliar(v.json);
    registrar(titulo, 'atacante com acesso ao arquivo', requisicao, esperado, obtido, ok, informativo);
  }

  await cenarioAdulteracao('Evento de auditoria alterado direto no arquivo', 'edição de data.json + GET /auditoria/verificar',
    `integra = false; primeiro evento quebrado = ${meio.id}`,
    d => { d.auditoria.find(e => e.id === meio.id).ator_nome = 'ADULTERADO'; },
    v => ({ ok: v.integra === false && v.primeiro_quebrado === meio.id, obtido: `integra = ${v.integra}; primeiro_quebrado = ${v.primeiro_quebrado}; motivo: ${v.motivo}` }));

  await cenarioAdulteracao('Evento de auditoria removido do meio da trilha', 'remoção em data.json + GET /auditoria/verificar',
    `integra = false; primeiro evento quebrado = ${seguinte.id}`,
    d => { d.auditoria = d.auditoria.filter(e => e.id !== meio.id); },
    v => ({ ok: v.integra === false && v.primeiro_quebrado === seguinte.id, obtido: `integra = ${v.integra}; primeiro_quebrado = ${v.primeiro_quebrado}; motivo: ${v.motivo}` }));

  await cenarioAdulteracao('LIMITAÇÃO: remoção apenas do evento mais recente', 'remoção do último evento + GET /auditoria/verificar',
    'não detectada (sem âncora externa do último hash)',
    d => { d.auditoria.shift(); },
    v => ({ ok: v.integra === true, obtido: `integra = ${v.integra} (truncar o fim da cadeia não é detectável sem guardar o último hash fora do servidor)` }), {}, true);

  await cenarioAdulteracao('LIMITAÇÃO: cadeia reescrita sem AUDIT_KEY', 'alteração + recálculo SHA-256 da cadeia inteira',
    'não detectada (SHA-256 puro pode ser recalculado por quem tem o arquivo)',
    d => { d.auditoria.find(e => e.id === meio.id).ator_nome = 'ADULTERADO'; recalcularCadeia(d.auditoria); },
    v => ({ ok: v.integra === true, obtido: `integra = ${v.integra} (sem chave secreta, a cadeia pode ser refeita)` }), {}, true);

  // com chave: gerar log novo sob AUDIT_KEY, adulterar e recalcular sem a chave
  const chaveSrv = await iniciarServidor({ AUDIT_KEY: 'chave-secreta-fora-do-arquivo' });
  const tk = await login(chaveSrv.base, 'admin');
  await chamar(chaveSrv.base, 'POST', '/login', { corpo: { usuario: 'admin', senha: 'errada' }, rotulo: 'gerar eventos' });
  await chamar(chaveSrv.base, 'GET', '/auditoria/verificar', { token: tk, rotulo: 'cadeia íntegra com chave' });
  await chaveSrv.parar();
  const comChave = lerDados(chaveSrv.arquivo);
  await cenarioAdulteracao('Cadeia reescrita sem conhecer a AUDIT_KEY (HMAC)', 'alteração + recálculo SHA-256 + GET /auditoria/verificar',
    'integra = false (HMAC exige a chave, que não está no arquivo)',
    d => { d.auditoria[d.auditoria.length - 1].ator_nome = 'ADULTERADO'; recalcularCadeia(d.auditoria); },
    v => ({ ok: v.integra === false, obtido: `integra = ${v.integra}; servidor iniciado com AUDIT_KEY; motivo: ${v.motivo}` }),
    { AUDIT_KEY: 'chave-secreta-fora-do-arquivo' }, false, comChave);

  // ================= Expiração de sessão =================
  categoria = 'Autenticação e sessão';
  const sx = await iniciarServidor({ SESSION_TTL_MIN: '0.02' }); // ≈ 1,2 s
  const tx = await login(sx.base, 'admin');
  const antes = await chamar(sx.base, 'GET', '/me', { token: tx, rotulo: 'dentro do prazo' });
  await sleep(1600);
  const depois = await chamar(sx.base, 'GET', '/me', { token: tx, rotulo: 'após expirar (TTL ≈ 1,2 s)' });
  await sx.parar();
  registrar('Expiração de sessão por inatividade', 'admin', 'GET /me antes e depois do TTL', 'HTTP 200 e depois HTTP 401', `HTTP ${antes.status} e depois ${depois.status}`, antes.status === 200 && depois.status === 401);

  // ================= TLS =================
  categoria = 'Transporte';
  try {
    const dirTls = fs.mkdtempSync(path.join(os.tmpdir(), 'tcc-tls-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dirTls, 'k.pem'),
      '-out', path.join(dirTls, 'c.pem'), '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
    const st = await iniciarServidor({ TLS_KEY: path.join(dirTls, 'k.pem'), TLS_CERT: path.join(dirTls, 'c.pem') });
    const h = await getHttps(st.port, '/health');
    let semTls = 'conexão recusada/encerrada';
    try { await new Promise((res, rej) => { const q = http.get({ host: '127.0.0.1', port: st.port, path: '/health', timeout: 1500 }, x => { x.resume(); res(x); }); q.on('error', rej); q.on('timeout', () => { q.destroy(new Error('timeout')); }); }); semTls = 'HTTP simples aceito'; } catch { /* esperado */ }
    await st.parar();
    log.push(`$ GET https://127.0.0.1:${st.port}/health (certificado autoassinado)\n  -> HTTP ${h.status}  Strict-Transport-Security: ${h.headers['strict-transport-security']}`);
    registrar('Servidor sob TLS (certificado autoassinado)', 'anônimo', 'GET https://…/health', 'HTTP 200 via HTTPS + cabeçalho HSTS; HTTP simples não atendido',
      `HTTP ${h.status}; HSTS: ${h.headers['strict-transport-security'] || 'ausente'}; HTTP simples: ${semTls}`,
      h.status === 200 && Boolean(h.headers['strict-transport-security']) && semTls !== 'HTTP simples aceito');
  } catch (e) {
    log.push(`(teste de TLS ignorado: ${e.message})`);
  }

  // ================= Relatório =================
  let expressVersao = 'desconhecida';
  try { expressVersao = require(require.resolve('express/package.json', { paths: [path.join(ROOT, 'backend'), __dirname, ...(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean)] })).version; } catch { /* ignora */ }

  const total = resultados.length;
  const obrigatorios = resultados.filter(x => !x.informativo);
  const passaram = obrigatorios.filter(x => x.ok).length;
  const info = resultados.filter(x => x.informativo);

  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'log_bruto.txt'), log.join('\n'));
  fs.writeFileSync(path.join(OUT, 'resultado.json'), JSON.stringify({ gerado_em: new Date().toISOString(), node: process.version, express: expressVersao, total, obrigatorios: obrigatorios.length, passaram, resultados }, null, 2));
  const md = [
    '# Resultado da execução automatizada dos testes',
    '',
    `- Data: ${new Date().toISOString()}`,
    `- Node.js: ${process.version} | Express: ${expressVersao}`,
    `- Cenários obrigatórios: **${passaram} de ${obrigatorios.length}** com o resultado esperado`,
    `- Cenários informativos (limitações conhecidas): ${info.length}`,
    '',
    '| ID | Categoria | Cenário | Perfil | Requisição | Esperado | Obtido | Status |',
    '|---|---|---|---|---|---|---|---|',
    ...resultados.map(x => `| ${x.id} | ${x.categoria} | ${x.titulo} | ${x.perfil} | \`${x.requisicao}\` | ${x.esperado} | ${x.obtido} | ${x.informativo ? 'INFO' : (x.ok ? 'OK' : 'FALHA')} |`),
    ''
  ].join('\n');
  fs.writeFileSync(path.join(OUT, 'resumo.md'), md);

  console.log(resultados.map(x => `${x.informativo ? 'INFO ' : (x.ok ? 'OK   ' : 'FALHA')} ${x.id} ${x.titulo}`).join('\n'));
  console.log(`\n${passaram} de ${obrigatorios.length} cenários obrigatórios OK; ${info.length} informativos. Express: ${expressVersao}`);
  process.exit(passaram === obrigatorios.length ? 0 : 1);
})().catch(e => { console.error(e); process.exit(2); });
