const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
const dataFile = process.env.DATA_FILE ? path.resolve(process.env.DATA_FILE) : path.join(__dirname, 'data.json');
const frontendDir = path.join(__dirname, '..', 'frontend');

const DEFAULT_DEMO_PASSWORD = process.env.DEMO_PASSWORD || '123456';
const INTERNAL_ROLES = new Set(['admin', 'rh', 'portaria', 'colaborador']);
const sessions = new Map();

// Parâmetros de segurança configuráveis por variável de ambiente.
const SESSION_TTL_MS = (Number(process.env.SESSION_TTL_MIN) || 30) * 60 * 1000;   // expiração por inatividade
const LOGIN_MAX_FAILS = Number(process.env.LOGIN_MAX_FAILS) || 5;                 // falhas toleradas por janela
const LOGIN_WINDOW_MS = (Number(process.env.LOGIN_WINDOW_MIN) || 15) * 60 * 1000; // janela de contagem/bloqueio
const AUDIT_KEY = process.env.AUDIT_KEY || null;                                   // chave opcional (HMAC) do encadeamento
const USE_TLS = Boolean(process.env.TLS_KEY && process.env.TLS_CERT);
const loginFails = new Map();

const initialData = {
  usuarios: [
    { id: 1, nome: 'Gabrieli Botam', cpf: '100.000.000-01', email: 'gabrieli@demo.local', usuario: 'admin', tipo: 'admin', setor: 'Administração', ativo: true, possui_carro: false },
    { id: 2, nome: 'Nathan Souza', cpf: '200.000.000-02', email: 'nathan@demo.local', usuario: 'portaria', tipo: 'portaria', setor: 'Portaria', ativo: true, possui_carro: false },
    { id: 3, nome: 'Solon Thomas', cpf: '300.000.000-03', email: 'solon@demo.local', usuario: 'rh', tipo: 'rh', setor: 'RH', ativo: true, possui_carro: false },
    { id: 4, nome: 'Jaiane Americo', cpf: '400.000.000-04', email: 'jaiane@demo.local', usuario: 'jaiane', tipo: 'visitante', setor: 'Comercial', ativo: true, possui_carro: false },
    { id: 5, nome: 'Matheus Beraldo', cpf: '500.000.000-05', email: 'matheus@demo.local', usuario: 'matheus', tipo: 'fornecedor', empresa: 'Empresa Demonstração', ativo: true, possui_carro: true, placa: 'ABC1D23', modelo: 'Fiorino', cor: 'Branca' }
  ],
  registros: [],
  agendamentos: [],
  auditoria: []
};

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, expectedHex] = stored.split(':');
  const actual = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

// ---- Trilha de auditoria com encadeamento de hashes (tamper-evident) -------------------------
// Cada evento guarda o hash do evento anterior; alterar, remover ou reordenar qualquer evento
// rompe a cadeia e é detectado por verifyAuditChain(). Com AUDIT_KEY definida usa-se HMAC-SHA256,
// de modo que quem só tem acesso ao arquivo data.json não consegue recalcular a cadeia.
const AUDIT_FIELDS = ['id', 'ator_id', 'ator_nome', 'ator_tipo', 'acao', 'alvo_id', 'alvo_nome',
  'alvo_tipo', 'detalhes', 'ip_origem', 'quando', 'hash_anterior'];

function auditDigest(ev) {
  const canon = JSON.stringify(AUDIT_FIELDS.map(field => ev[field] ?? null));
  return AUDIT_KEY
    ? crypto.createHmac('sha256', AUDIT_KEY).update(canon).digest('hex')
    : crypto.createHash('sha256').update(canon).digest('hex');
}

function verifyAuditChain() {
  const eventos = [...data.auditoria].reverse(); // do mais antigo para o mais recente
  let anterior = null;
  for (const ev of eventos) {
    if ((ev.hash_anterior ?? null) !== anterior) {
      return { integra: false, total: eventos.length, primeiro_quebrado: ev.id,
        motivo: 'encadeamento rompido (evento removido, inserido ou reordenado)' };
    }
    if (auditDigest(ev) !== ev.hash) {
      return { integra: false, total: eventos.length, primeiro_quebrado: ev.id,
        motivo: 'conteúdo do evento alterado' };
    }
    anterior = ev.hash;
  }
  return { integra: true, total: eventos.length, ultimo_hash: anterior,
    algoritmo: AUDIT_KEY ? 'HMAC-SHA256' : 'SHA-256' };
}

function loadData() {
  if (!fs.existsSync(dataFile)) fs.writeFileSync(dataFile, JSON.stringify(initialData, null, 2));
  const loaded = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  loaded.usuarios ||= [];
  loaded.registros ||= [];
  loaded.agendamentos ||= [];
  loaded.auditoria ||= [];
  loaded.usuarios_excluidos ||= [];       // exclusão lógica: cadastros arquivados, não apagados
  loaded.agendamentos_cancelados ||= [];  // cancelamentos arquivados, não apagados

  // Migração dos usuários de demonstração para credenciais com senha.
  let changed = false;

  // Migração: eventos de auditoria antigos (sem hash) são selados em ordem cronológica.
  let anteriorHash = null;
  for (const ev of [...loaded.auditoria].reverse()) {
    if (!ev.hash) {
      ev.hash_anterior = anteriorHash;
      ev.hash = auditDigest(ev);
      changed = true;
    }
    anteriorHash = ev.hash;
  }
  loaded.usuarios.forEach(user => {
    if (INTERNAL_ROLES.has(String(user.tipo).toLowerCase()) && !user.senha_hash) {
      user.senha_hash = hashPassword(DEFAULT_DEMO_PASSWORD);
      changed = true;
    }
  });
  if (changed) fs.writeFileSync(dataFile, JSON.stringify(loaded, null, 2));
  return loaded;
}

let data = loadData();
const saveData = () => fs.writeFileSync(dataFile, JSON.stringify(data, null, 2));
const nextId = items => items.reduce((max, item) => Math.max(max, Number(item.id) || 0), 0) + 1;

function publicUser(user) {
  if (!user) return null;
  const { foto, senha_hash, ...safe } = user;
  return {
    ...safe,
    foto_base64: foto || null,
    carro: user.possui_carro ? { placa: user.placa, modelo: user.modelo, cor: user.cor } : null
  };
}

function currentUser(req) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const sessao = sessions.get(token);
  if (!sessao) return null;
  if (sessao.expiraEm < Date.now()) { sessions.delete(token); return null; }
  sessao.expiraEm = Date.now() + SESSION_TTL_MS; // renova a cada uso (expira por inatividade)
  const userId = sessao.userId;
  return data.usuarios.find(user => user.id === userId && user.ativo !== false) || null;
}

function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Não autenticado' });
  req.user = user;
  next();
}

function requireRole(...roles) {
  const allowed = new Set(roles.map(role => role.toLowerCase()));
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Não autenticado' });
    if (!allowed.has(String(req.user.tipo).toLowerCase())) {
      audit(req, 'ACESSO_NEGADO', null, `${req.method} ${req.path}`);
      saveData();
      return res.status(403).json({ error: 'Usuário sem permissão para esta operação' });
    }
    next();
  };
}

// Perfis com visão operacional completa (Tabela 2). Os demais enxergam apenas os próprios dados.
const PRIVILEGED_ROLES = new Set(['admin', 'rh', 'portaria']);
const roleOf = user => String(user?.tipo || '').toLowerCase();
const isPrivileged = user => PRIVILEGED_ROLES.has(roleOf(user));
const isSelf = (user, id) => Number(id) === user.id;

// Autorização por objeto (anti-BOLA): nega e audita o acesso a dados de outra pessoa.
function denyOtherUser(req, res, alvoId) {
  const alvo = data.usuarios.find(item => item.id === Number(alvoId));
  audit(req, 'ACESSO_NEGADO', alvo || null, `${req.method} ${req.originalUrl} (dados de outro usuário)`);
  saveData();
  return res.status(403).json({ error: 'Sem permissão para acessar dados de outro usuário' });
}

// Quem pode criar/alterar/excluir contas de cada perfil (anti-escalada de privilégio).
function canManageType(actor, tipo) {
  const role = roleOf(actor);
  const target = String(tipo || '').toLowerCase();
  if (role === 'admin') return true;
  if (role === 'rh') return target !== 'admin';
  if (role === 'portaria') return ['visitante', 'fornecedor'].includes(target);
  return false;
}
function denyManage(req, res, alvo) {
  audit(req, 'ACESSO_NEGADO', alvo || null, `${req.method} ${req.originalUrl} (gestão de perfil não permitida)`);
  saveData();
  return res.status(403).json({ error: 'Sem permissão para gerenciar este perfil de usuário' });
}

function clientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '') || null;
}

function audit(req, acao, alvo, detalhes, actorOverride = null) {
  const actor = actorOverride || req.user || req.actor || currentUser(req);
  // Sem ator identificado só registramos falhas de autenticação (ator desconhecido).
  if (!actor && !['FALHA_LOGIN', 'LOGIN_BLOQUEADO'].includes(acao)) return;
  const evento = {
    id: nextId(data.auditoria),
    ator_id: actor ? actor.id : null,
    ator_nome: actor ? actor.nome : null,
    ator_tipo: actor ? actor.tipo : null,
    acao,
    alvo_id: alvo?.id || null,
    alvo_nome: alvo?.nome || null,
    alvo_tipo: alvo?.tipo || null,
    detalhes: detalhes || null,
    ip_origem: clientIp(req),
    quando: new Date().toISOString(),
    hash_anterior: data.auditoria[0]?.hash ?? null
  };
  evento.hash = auditDigest(evento);
  data.auditoria.unshift(evento);
}

function normalizeAction(value) {
  return String(value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (USE_TLS) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/health', (_req, res) => res.json({ status: 'ok', modo: 'local' }));

// Limite de tentativas de login por IP + login informado (em memória).
function loginBlockedSeconds(key) {
  const recentes = (loginFails.get(key) || []).filter(t => t > Date.now() - LOGIN_WINDOW_MS);
  loginFails.set(key, recentes);
  return recentes.length >= LOGIN_MAX_FAILS
    ? Math.ceil((recentes[0] + LOGIN_WINDOW_MS - Date.now()) / 1000)
    : 0;
}

app.post('/login', (req, res) => {
  const login = String(req.body.email || req.body.usuario || '').trim().toLowerCase();
  const password = String(req.body.senha || '');
  const user = data.usuarios.find(item =>
    String(item.email || '').toLowerCase() === login ||
    String(item.usuario || '').toLowerCase() === login
  );

  const chave = `${clientIp(req)}|${login}`;
  const espera = loginBlockedSeconds(chave);
  if (espera > 0) {
    audit(req, 'LOGIN_BLOQUEADO', user ? { id: user.id, nome: user.nome, tipo: user.tipo } : null,
      `Excesso de tentativas com login "${login.slice(0, 60)}"`);
    saveData();
    res.setHeader('Retry-After', String(espera));
    return res.status(429).json({ error: 'Muitas tentativas de login. Tente novamente mais tarde.' });
  }

  if (!user || user.ativo === false || !user.senha_hash || !verifyPassword(password, user.senha_hash)) {
    loginFails.set(chave, [...(loginFails.get(chave) || []), Date.now()]);
    audit(req, 'FALHA_LOGIN', user ? { id: user.id, nome: user.nome, tipo: user.tipo } : null,
      `Tentativa com login "${login.slice(0, 60)}"`);
    saveData();
    return res.status(401).json({ error: 'Usuário ou senha inválidos' });
  }

  loginFails.delete(chave);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, expiraEm: Date.now() + SESSION_TTL_MS });
  audit(req, 'LOGIN', user, null, user);
  saveData();

  res.json({ token, usuario: publicUser(user) });
});

app.post('/logout', requireAuth, (req, res) => {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  sessions.delete(token);
  audit(req, 'LOGOUT', req.user);
  saveData();
  res.json({ success: true });
});

app.get('/me', requireAuth, (req, res) => res.json(publicUser(req.user)));

app.get('/usuarios', requireAuth, (req, res) => {
  if (isPrivileged(req.user)) return res.json(data.usuarios.map(publicUser));

  // Demais perfis: apenas o próprio cadastro. O colaborador também recebe a lista mínima
  // (id, nome, tipo) de visitantes e fornecedores, necessária para criar agendamentos.
  const lista = [publicUser(req.user)];
  if (roleOf(req.user) === 'colaborador') {
    data.usuarios
      .filter(item => ['visitante', 'fornecedor'].includes(roleOf(item)) && item.ativo !== false)
      .forEach(item => lista.push({ id: item.id, nome: item.nome, tipo: item.tipo, ativo: item.ativo }));
  }
  res.json(lista);
});

app.get('/usuarios-agendados-hoje', requireAuth, requireRole('admin', 'rh', 'portaria'), (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.json(data.agendamentos
    .filter(item => item.data_agendada === today)
    .map(item => ({ ...item, ...publicUser(data.usuarios.find(user => user.id === item.usuario_id)) })));
});

app.get('/usuarios/:id', requireAuth, (req, res) => {
  if (!isPrivileged(req.user) && !isSelf(req.user, req.params.id)) return denyOtherUser(req, res, req.params.id);
  const user = data.usuarios.find(item => item.id === Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  res.json(publicUser(user));
});

function userFromBody(body, existing = {}) {
  const hasCar = body.possuiCarro === true || body.possuiCarro === 'true' || body.possui_carro === true;
  const tipo = String(body.tipo ?? existing.tipo ?? 'visitante').toLowerCase();
  const result = {
    ...existing,
    nome: body.nome ?? existing.nome,
    cpf: body.cpf ?? existing.cpf,
    email: body.email ?? existing.email,
    usuario: body.usuario || existing.usuario || String(body.email || '').split('@')[0],
    tipo,
    setor: body.setor ?? existing.setor ?? null,
    empresa: body.empresa ?? existing.empresa ?? null,
    ativo: existing.ativo ?? true,
    possui_carro: hasCar,
    placa: hasCar ? body.placa ?? existing.placa ?? null : null,
    modelo: hasCar ? body.modelo ?? existing.modelo ?? null : null,
    cor: hasCar ? body.cor ?? existing.cor ?? null : null
  };

  if (body.senha) result.senha_hash = hashPassword(body.senha);
  return result;
}

// Compara apenas campos preenchidos: dois cadastros sem e-mail (ou sem login) não são "duplicados".
function validateUniqueUser(user, ignoreId = null) {
  const digits = value => String(value || '').replace(/\D/g, '');
  const lower = value => String(value || '').trim().toLowerCase();
  return data.usuarios.find(item =>
    item.id !== ignoreId &&
    ((digits(user.cpf) && digits(item.cpf) === digits(user.cpf)) ||
     (lower(user.email) && lower(item.email) === lower(user.email)) ||
     (lower(user.usuario) && lower(item.usuario) === lower(user.usuario)))
  );
}

// Login gerado a partir do e-mail: se já existir (joao@a.com e joao@b.com), acrescenta um número.
function uniqueUsername(base) {
  const raiz = String(base || 'usuario').trim() || 'usuario';
  let candidato = raiz;
  let n = 1;
  while (data.usuarios.some(item => String(item.usuario || '').toLowerCase() === candidato.toLowerCase())) {
    candidato = `${raiz}${++n}`;
  }
  return candidato;
}

app.post('/usuarios', requireAuth, requireRole('admin', 'rh', 'portaria'), upload.single('foto'), (req, res) => {
  if (!req.body.nome || !req.body.cpf || !req.body.email) {
    return res.status(400).json({ error: 'Preencha nome, CPF e e-mail' });
  }

  const tipo = String(req.body.tipo || 'visitante').toLowerCase();
  if (!canManageType(req.user, tipo)) return denyManage(req, res, { nome: req.body.nome, tipo });
  if (INTERNAL_ROLES.has(tipo) && !req.body.senha) {
    return res.status(400).json({ error: 'Senha obrigatória para usuários internos' });
  }

  const user = { ...userFromBody(req.body), id: nextId(data.usuarios) };
  if (!req.body.usuario) user.usuario = uniqueUsername(user.usuario);
  const duplicate = validateUniqueUser(user);
  if (duplicate) return res.status(409).json({ error: 'CPF, e-mail ou usuário já cadastrado' });

  if (req.file) user.foto = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
  data.usuarios.push(user);
  audit(req, 'CADASTRO_USUARIO', user);
  saveData();
  res.status(201).json({ success: true, message: 'Usuário cadastrado com sucesso', userId: user.id });
});

app.put('/usuarios/:id', requireAuth, requireRole('admin', 'rh', 'portaria'), upload.single('foto'), (req, res) => {
  const index = data.usuarios.findIndex(item => item.id === Number(req.params.id));
  if (index < 0) return res.status(404).json({ error: 'Usuário não encontrado' });

  const existing = data.usuarios[index];
  const novoTipo = String(req.body.tipo ?? existing.tipo).toLowerCase();
  if (!canManageType(req.user, existing.tipo) || !canManageType(req.user, novoTipo)) return denyManage(req, res, existing);
  const user = userFromBody(req.body, existing);

  if (!req.body.senha && req.body.manterSenha !== 'true') {
    if (INTERNAL_ROLES.has(String(existing.tipo).toLowerCase())) {
      user.senha_hash = existing.senha_hash;
    } else {
      delete user.senha_hash;
    }
  }

  if (req.body.manterFoto === 'false') delete user.foto;
  if (req.file) user.foto = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;

  const duplicate = validateUniqueUser(user, existing.id);
  if (duplicate) return res.status(409).json({ error: 'CPF, e-mail ou usuário já cadastrado' });

  data.usuarios[index] = user;
  audit(req, 'ATUALIZACAO_USUARIO', user);
  saveData();
  res.json({ success: true, message: 'Usuário atualizado com sucesso' });
});

app.put('/usuarios/:id/toggle-ativo', requireAuth, requireRole('admin', 'rh'), (req, res) => {
  const user = data.usuarios.find(item => item.id === Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  if (!canManageType(req.user, user.tipo)) return denyManage(req, res, user);
  user.ativo = !user.ativo;
  audit(req, user.ativo ? 'ATIVACAO_USUARIO' : 'DESATIVACAO_USUARIO', user);
  saveData();
  res.json({ success: true, ativo: user.ativo });
});

app.delete('/usuarios/:id', requireAuth, requireRole('admin', 'rh'), (req, res) => {
  const id = Number(req.params.id);
  const user = data.usuarios.find(item => item.id === id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  if (!canManageType(req.user, user.tipo)) return denyManage(req, res, user);

  // O histórico não é apagado: mantém rastreabilidade dos eventos anteriores.
  // Exclusão lógica: o cadastro sai da lista ativa e é arquivado (sem a credencial).
  const { senha_hash, ...arquivado } = user;
  data.usuarios_excluidos.push({
    ...arquivado,
    excluido_em: new Date().toISOString(),
    excluido_por: req.user.id,
    excluido_por_nome: req.user.nome
  });
  data.usuarios = data.usuarios.filter(item => item.id !== id);
  audit(req, 'EXCLUSAO_USUARIO', user, 'Cadastro arquivado (exclusão lógica); históricos de acesso e agendamentos foram preservados.');
  saveData();
  res.json({ success: true, message: 'Usuário excluído (arquivado); histórico preservado' });
});

app.get(['/carro/:usuarioId', '/veiculo/:usuarioId'], requireAuth, (req, res) => {
  if (!isPrivileged(req.user) && !isSelf(req.user, req.params.usuarioId)) return denyOtherUser(req, res, req.params.usuarioId);
  const user = data.usuarios.find(item => item.id === Number(req.params.usuarioId));
  if (!user?.possui_carro) return res.status(404).json({ message: 'Veículo não encontrado', possui_carro: false });
  res.json({ placa: user.placa, modelo: user.modelo, cor: user.cor, possui_carro: true });
});

app.post('/registros', requireAuth, requireRole('admin', 'portaria'), (req, res) => {
  const user = data.usuarios.find(item => item.id === Number(req.body.usuario_id));
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  if (user.ativo === false) return res.status(400).json({ error: 'Usuário inativo não pode registrar acesso' });

  const action = normalizeAction(req.body.acao);
  if (!['entrada', 'saida'].includes(action)) return res.status(400).json({ error: 'Ação inválida' });

  const ultimo = data.registros.find(item => item.usuario_id === user.id);
  if (action === 'entrada' && ultimo?.acao === 'entrada' && !ultimo?.cancelado) {
    return res.status(409).json({ error: 'Já existe uma entrada aberta para este usuário' });
  }
  if (action === 'saida' && (!ultimo || ultimo.acao !== 'entrada' || ultimo.cancelado)) {
    return res.status(409).json({ error: 'Não existe uma entrada aberta para este usuário' });
  }

  const record = {
    id: nextId(data.registros),
    usuario_id: user.id,
    nome: user.nome,
    cpf: user.cpf,
    tipo: user.tipo,
    acao: action,
    data_hora: new Date().toISOString(),
    registrado_por: req.user.id,
    registrado_por_nome: req.user.nome
  };

  data.registros.unshift(record);
  audit(req, action === 'entrada' ? 'REGISTRO_ENTRADA' : 'REGISTRO_SAIDA', user);
  saveData();
  res.status(201).json(record);
});

app.get('/registros/ultimo', requireAuth, (req, res) => {
  if (!isPrivileged(req.user) && !isSelf(req.user, req.query.usuario_id)) return denyOtherUser(req, res, req.query.usuario_id);
  res.json(data.registros.find(item => item.usuario_id === Number(req.query.usuario_id)) || null);
});

app.get('/registros/abertos', requireAuth, (req, res) => {
  if (!isPrivileged(req.user) && !isSelf(req.user, req.query.usuario_id)) return denyOtherUser(req, res, req.query.usuario_id);
  const records = data.registros.filter(item => item.usuario_id === Number(req.query.usuario_id));
  res.json(records[0]?.acao === 'entrada' && !records[0]?.cancelado ? [records[0]] : []);
});

app.get('/registros', requireAuth, (req, res) => {
  let result = [...data.registros];
  if (!isPrivileged(req.user)) {
    // Sem permissão operacional: só o próprio histórico, mesmo que outro usuario_id seja informado.
    if (req.query.usuario_id && !isSelf(req.user, req.query.usuario_id)) return denyOtherUser(req, res, req.query.usuario_id);
    result = result.filter(item => item.usuario_id === req.user.id);
  }
  if (req.query.usuario_id) result = result.filter(item => item.usuario_id === Number(req.query.usuario_id));
  if (req.query.limit) result = result.slice(0, Math.min(Number(req.query.limit), 1000));
  res.json(result);
});

// Não existe exclusão física de registros de acesso. A rastreabilidade é preservada.
app.delete('/registros/:id', requireAuth, requireRole('admin'), (_req, res) =>
  res.status(405).json({ error: 'Registros de acesso são imutáveis para preservar a rastreabilidade' })
);

app.post('/agendar', requireAuth, requireRole('admin', 'rh', 'colaborador'), (req, res) => {
  const user = data.usuarios.find(item => item.id === Number(req.body.usuario_id));
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  if (!['visitante', 'fornecedor'].includes(String(user.tipo).toLowerCase())) {
    return res.status(400).json({ error: 'Agendamento disponível apenas para visitantes e fornecedores' });
  }
  if (!req.body.data_agendada || !req.body.hora_agendada || !req.body.destino) {
    return res.status(400).json({ error: 'Data, hora e destino são obrigatórios' });
  }

  const appointment = {
    id: nextId(data.agendamentos),
    usuario_id: user.id,
    nome: user.nome,
    responsavel_id: req.user.id,
    responsavel_nome: req.user.nome,
    data_agendada: req.body.data_agendada,
    hora_agendada: req.body.hora_agendada,
    destino: req.body.destino
  };

  data.agendamentos.push(appointment);
  audit(req, 'CRIACAO_AGENDAMENTO', user, `Destino: ${appointment.destino}; Data: ${appointment.data_agendada}; Hora: ${appointment.hora_agendada}`);
  saveData();
  res.status(201).json({ success: true, message: 'Agendamento criado com sucesso', ...appointment });
});

app.get('/agendamentos', requireAuth, (req, res) => {
  if (isPrivileged(req.user)) return res.json(data.agendamentos);
  // Colaborador: agendamentos pelos quais é responsável; visitante/fornecedor: os próprios.
  res.json(data.agendamentos.filter(item =>
    item.usuario_id === req.user.id || item.responsavel_id === req.user.id));
});

app.delete('/agendamentos/:id', requireAuth, (req, res) => {
  const index = data.agendamentos.findIndex(item => item.id === Number(req.params.id));
  if (index < 0) return res.status(404).json({ error: 'Agendamento não encontrado' });
  const appointment = data.agendamentos[index];

  const canDelete = ['admin', 'rh'].includes(String(req.user.tipo).toLowerCase()) ||
    appointment.responsavel_id === req.user.id;
  if (!canDelete) return res.status(403).json({ error: 'Sem permissão para cancelar este agendamento' });

  data.agendamentos.splice(index, 1);
  data.agendamentos_cancelados.push({
    ...appointment,
    cancelado_em: new Date().toISOString(),
    cancelado_por: req.user.id,
    cancelado_por_nome: req.user.nome
  });
  audit(req, 'EXCLUSAO_AGENDAMENTO', { id: appointment.usuario_id, nome: appointment.nome, tipo: 'visitante' },
    `Agendamento ${appointment.id} cancelado.`);
  saveData();
  res.json({ success: true, message: 'Agendamento cancelado' });
});

app.get('/auditoria', requireAuth, requireRole('admin'), (req, res) => {
  let result = [...data.auditoria];
  if (req.query.acao) result = result.filter(item => item.acao.includes(String(req.query.acao).toUpperCase()));
  if (req.query.q) result = result.filter(item => JSON.stringify(item).toLowerCase().includes(String(req.query.q).toLowerCase()));

  const de = req.query.de ? new Date(`${req.query.de}T00:00:00`) : null;
  const ate = req.query.ate ? new Date(`${req.query.ate}T23:59:59.999`) : null;
  if (de && !Number.isNaN(de.getTime())) result = result.filter(item => new Date(item.quando) >= de);
  if (ate && !Number.isNaN(ate.getTime())) result = result.filter(item => new Date(item.quando) <= ate);

  const limit = Math.min(Math.max(Number(req.query.limit) || 400, 1), 1000);
  res.json(result.slice(0, limit));
});

// Verificação de integridade da trilha (encadeamento de hashes). Somente admin.
app.get('/auditoria/verificar', requireAuth, requireRole('admin'), (req, res) => {
  const resultado = verifyAuditChain();
  audit(req, 'VERIFICACAO_AUDITORIA', null,
    resultado.integra ? `Cadeia íntegra (${resultado.total} eventos)` : `Cadeia ROMPIDA no evento ${resultado.primeiro_quebrado}: ${resultado.motivo}`);
  saveData();
  res.json(resultado);
});

// A auditoria é somente leitura; não há exclusão física de eventos.
app.delete('/auditoria/:id', requireAuth, requireRole('admin'), (_req, res) =>
  res.status(405).json({ error: 'Eventos de auditoria são imutáveis' })
);
app.delete('/auditoria', requireAuth, requireRole('admin'), (_req, res) =>
  res.status(405).json({ error: 'Eventos de auditoria são imutáveis' })
);

app.use(express.static(frontendDir));
app.get('/', (_req, res) => res.sendFile(path.join(frontendDir, 'login.html')));
app.use((_req, res) => res.status(404).json({ error: 'Rota não encontrada' }));

function startServer() {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const aviso = protocolo => console.log(`Sistema de controle de acesso iniciado em ${protocolo}://${host}:${port}`);
  if (USE_TLS) {
    require('https')
      .createServer({ key: fs.readFileSync(process.env.TLS_KEY), cert: fs.readFileSync(process.env.TLS_CERT) }, app)
      .listen(port, host, () => aviso('https'));
  } else {
    app.listen(port, host, () => aviso('http'));
  }
}

if (require.main === module) startServer();

module.exports = { app, hashPassword, verifyPassword, verifyAuditChain, startServer };
