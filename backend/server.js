const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
const dataFile = path.join(__dirname, 'data.json');
const frontendDir = path.join(__dirname, '..', 'frontend');

const DEFAULT_DEMO_PASSWORD = process.env.DEMO_PASSWORD || '123456';
const INTERNAL_ROLES = new Set(['admin', 'rh', 'portaria', 'colaborador']);
const sessions = new Map();

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

function loadData() {
  if (!fs.existsSync(dataFile)) fs.writeFileSync(dataFile, JSON.stringify(initialData, null, 2));
  const loaded = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  loaded.usuarios ||= [];
  loaded.registros ||= [];
  loaded.agendamentos ||= [];
  loaded.auditoria ||= [];

  // Migração dos usuários de demonstração para credenciais com senha.
  let changed = false;
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
  const userId = sessions.get(token);
  if (!userId) return null;
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
      return res.status(403).json({ error: 'Usuário sem permissão para esta operação' });
    }
    next();
  };
}

function audit(req, acao, alvo, detalhes) {
  const actor = req.user || req.actor || currentUser(req);
  if (!actor) return;
  data.auditoria.unshift({
    id: nextId(data.auditoria),
    ator_id: actor.id,
    ator_nome: actor.nome,
    ator_tipo: actor.tipo,
    acao,
    alvo_id: alvo?.id || null,
    alvo_nome: alvo?.nome || null,
    alvo_tipo: alvo?.tipo || null,
    detalhes: detalhes || null,
    quando: new Date().toISOString()
  });
}

function normalizeAction(value) {
  return String(value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/health', (_req, res) => res.json({ status: 'ok', modo: 'local' }));

app.post('/login', (req, res) => {
  const login = String(req.body.email || req.body.usuario || '').trim().toLowerCase();
  const password = String(req.body.senha || '');
  const user = data.usuarios.find(item =>
    String(item.email || '').toLowerCase() === login ||
    String(item.usuario || '').toLowerCase() === login
  );

  if (!user || user.ativo === false || !user.senha_hash || !verifyPassword(password, user.senha_hash)) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  audit({ actor: user }, 'LOGIN', user);
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
  res.json(data.usuarios.map(publicUser));
});

app.get('/usuarios-agendados-hoje', requireAuth, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.json(data.agendamentos
    .filter(item => item.data_agendada === today)
    .map(item => ({ ...item, ...publicUser(data.usuarios.find(user => user.id === item.usuario_id)) })));
});

app.get('/usuarios/:id', requireAuth, (req, res) => {
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
    usuario: body.usuario ?? existing.usuario ?? String(body.email || '').split('@')[0],
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

function validateUniqueUser(user, ignoreId = null) {
  const duplicate = data.usuarios.find(item =>
    item.id !== ignoreId &&
    (String(item.cpf || '').replace(/\D/g, '') === String(user.cpf || '').replace(/\D/g, '') ||
     String(item.email || '').toLowerCase() === String(user.email || '').toLowerCase() ||
     String(item.usuario || '').toLowerCase() === String(user.usuario || '').toLowerCase())
  );
  return duplicate;
}

app.post('/usuarios', requireAuth, requireRole('admin', 'rh', 'portaria'), upload.single('foto'), (req, res) => {
  if (!req.body.nome || !req.body.cpf || !req.body.email) {
    return res.status(400).json({ error: 'Preencha nome, CPF e e-mail' });
  }

  const tipo = String(req.body.tipo || 'visitante').toLowerCase();
  if (INTERNAL_ROLES.has(tipo) && !req.body.senha) {
    return res.status(400).json({ error: 'Senha obrigatória para usuários internos' });
  }

  const user = { ...userFromBody(req.body), id: nextId(data.usuarios) };
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
  user.ativo = !user.ativo;
  audit(req, user.ativo ? 'ATIVACAO_USUARIO' : 'DESATIVACAO_USUARIO', user);
  saveData();
  res.json({ success: true, ativo: user.ativo });
});

app.delete('/usuarios/:id', requireAuth, requireRole('admin', 'rh'), (req, res) => {
  const id = Number(req.params.id);
  const user = data.usuarios.find(item => item.id === id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  // O histórico não é apagado: mantém rastreabilidade dos eventos anteriores.
  data.usuarios = data.usuarios.filter(item => item.id !== id);
  audit(req, 'EXCLUSAO_USUARIO', user, 'Cadastro excluído; históricos de acesso e agendamentos foram preservados.');
  saveData();
  res.json({ success: true, message: 'Usuário excluído; histórico preservado' });
});

app.get(['/carro/:usuarioId', '/veiculo/:usuarioId'], requireAuth, (req, res) => {
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

app.get('/registros/ultimo', requireAuth, (req, res) =>
  res.json(data.registros.find(item => item.usuario_id === Number(req.query.usuario_id)) || null)
);

app.get('/registros/abertos', requireAuth, (req, res) => {
  const records = data.registros.filter(item => item.usuario_id === Number(req.query.usuario_id));
  res.json(records[0]?.acao === 'entrada' && !records[0]?.cancelado ? [records[0]] : []);
});

app.get('/registros', requireAuth, (req, res) => {
  let result = [...data.registros];
  if (req.query.usuario_id) result = result.filter(item => item.usuario_id === Number(req.query.usuario_id));
  if (req.query.limit) result = result.slice(0, Math.min(Number(req.query.limit), 1000));
  res.json(result);
});

// Não existe exclusão física de registros de acesso. A rastreabilidade é preservada.
app.delete('/registros/:id', requireAuth, requireRole('admin'), (_req, res) =>
  res.status(405).json({ error: 'Registros de acesso são imutáveis para preservar a rastreabilidade' })
);

app.post('/agendar', requireAuth, (req, res) => {
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

app.get('/agendamentos', requireAuth, (_req, res) => res.json(data.agendamentos));

app.delete('/agendamentos/:id', requireAuth, (req, res) => {
  const index = data.agendamentos.findIndex(item => item.id === Number(req.params.id));
  if (index < 0) return res.status(404).json({ error: 'Agendamento não encontrado' });
  const appointment = data.agendamentos[index];

  const canDelete = ['admin', 'rh'].includes(String(req.user.tipo).toLowerCase()) ||
    appointment.responsavel_id === req.user.id;
  if (!canDelete) return res.status(403).json({ error: 'Sem permissão para cancelar este agendamento' });

  data.agendamentos.splice(index, 1);
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

if (require.main === module) {
  app.listen(Number(process.env.PORT) || 3000, '127.0.0.1', () =>
    console.log('Sistema de controle de acesso iniciado na porta 3000')
  );
}

module.exports = { app, hashPassword, verifyPassword };
