const API = (window.API_BASE ?? '');

function authHeaders() {
  const t = localStorage.getItem('token');
  return t ? { Authorization: 'Bearer ' + t } : {};
}
function setMensagem(texto, ok = true) {
  const el = document.getElementById('mensagem');
  if (!el) return;
  el.textContent = (ok ? '✅ ' : '❌ ') + texto;
  el.style.color = ok ? 'green' : 'red';
}
function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
function norm(s) {
  return String(s || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .trim().toLowerCase();
}
const TIPOS_PERMITIDOS = new Set(['visitante', 'fornecedor']);

const form                 = document.getElementById('agendarForm');
const usuarioInput         = document.getElementById('usuario_nome');
const usuarioIdHidden      = document.getElementById('usuario_id');
const usuariosList         = document.getElementById('usuariosList');
const responsavelNomeInput = document.getElementById('responsavel');
const responsavelIdHidden  = document.getElementById('responsavel_id');
const listaAgendamentos    = document.getElementById('listaAgendamentos');
const formularioAgendar    = document.getElementById('formulario-agendar');
const btnNovoAgendamento   = document.getElementById('btn-novo-agendamento');
const btnNovoCadastro      = document.getElementById('btn-novo-cadastro');
const btnLogout            = document.getElementById('btn-logout');
const filtroTabela         = document.getElementById('filtroTabela');

let usuariosCache = [];       // SOMENTE visitantes/fornecedores (para o datalist/id)
let usuariosCacheTodos = [];  // TODOS (para fallbacks de empresa, etc.)
let token = localStorage.getItem('token');

function bloquearVoltaSeDeslogado() {
  window.addEventListener('pageshow', (e) => {
    if (e.persisted && !localStorage.getItem('token')) {
      window.location.replace('/login.html');
    }
  });

  try { history.pushState(null, '', location.href); } catch (_) {}
  window.addEventListener('popstate', () => {
    if (!localStorage.getItem('token')) {
      window.location.replace('/login.html');
    } else {
      try { history.pushState(null, '', location.href); } catch (_) {}
    }
  });
}

function hardLogout() {
  try {
    localStorage.removeItem('token');
    localStorage.removeItem('usuario_nome');
    localStorage.removeItem('usuario_tipo');
    localStorage.removeItem('usuario_id');
    sessionStorage && sessionStorage.clear?.();
  } catch (_) {}
  window.location.replace('/login.html');
}

function configurarFormularioAgendamento() {
  if (!formularioAgendar || !btnNovoAgendamento) return;

  formularioAgendar.style.display = 'none';
  btnNovoAgendamento.textContent = 'Novo Agendamento';

  btnNovoAgendamento.addEventListener('click', () => {
    const fechado = (formularioAgendar.style.display === 'none');
    formularioAgendar.style.display = fechado ? 'block' : 'none';
    btnNovoAgendamento.textContent = fechado ? 'Fechar Formulário' : 'Novo Agendamento';
  });
}

function getUsuarioIdByRotulo(rotulo) {
  const alvo = norm(rotulo);
  const user = usuariosCache.find(u => norm(`${u.nome} - ${u.tipo}`) === alvo);
  return user ? user.id : null;
}

async function carregarResponsavel() {
  try {
    if (!token) {
      const nomeLS = localStorage.getItem('usuario_nome');
      const idLS   = localStorage.getItem('usuario_id');
      if (nomeLS) responsavelNomeInput.value = nomeLS;
      if (idLS)   responsavelIdHidden.value  = idLS;
      return;
    }

    const res = await fetch(`${API}/me`, { headers: { ...authHeaders() } });
    if (!res.ok) return;

    const user = await res.json();
    if (user && user.id && user.nome) {
      responsavelNomeInput.value = user.nome;
      responsavelIdHidden.value  = user.id;
      localStorage.setItem('usuario_id',   user.id);
      localStorage.setItem('usuario_nome', user.nome);
    }
  } catch (err) {
    console.error('Erro ao carregar responsável:', err);
  }
}

async function carregarUsuarios() {
  try {
    const res = await fetch(`${API}/usuarios`, { headers: { ...authHeaders() } });
    if (!res.ok) throw new Error('Não foi possível carregar usuários');

    const data = await res.json();
    usuariosCacheTodos = Array.isArray(data) ? data : [];

    usuariosCache = usuariosCacheTodos.filter(u => TIPOS_PERMITIDOS.has(norm(u.tipo)));

    usuariosList.innerHTML = '';
    usuariosCache.forEach(u => {
      const option = document.createElement('option');
      option.value = `${u.nome} - ${u.tipo}`;
      usuariosList.appendChild(option);
    });

    if (usuariosCache.length === 0) {
      console.warn('Nenhum visitante/fornecedor cadastrado.');
    }
  } catch (err) {
    console.error('Erro ao carregar usuários:', err);
  }
}

async function carregarAgendamentos() {
  if (!listaAgendamentos) return;

  try {
    const res = await fetch(`${API}/agendamentos`, { headers: { ...authHeaders() } });
    if (!res.ok) throw new Error('Não foi possível carregar agendamentos');
    const agendamentos = await res.json();

    const usuarioLogadoNome = responsavelNomeInput.value;
    listaAgendamentos.innerHTML = '';

    agendamentos.forEach(a => {
      const dataFormatada = a.data_agendada
        ? new Date(a.data_agendada).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric' })
        : '—';

      let horaFormatada = a.hora_agendada || '—';
      if (horaFormatada && horaFormatada.length >= 5) {
        horaFormatada = horaFormatada.substring(0, 5);
      }

      let empresa = a.usuario_empresa || a.empresa || '';
      if ((!empresa || empresa === 'null') && usuariosCacheTodos?.length) {
        if (a.usuario_id) {
          const uById = usuariosCacheTodos.find(u => String(u.id) === String(a.usuario_id));
          empresa = uById?.empresa || empresa;
        }
        if ((!empresa || empresa === 'null') && a.usuario_nome) {
          const uByName = usuariosCacheTodos.find(u => norm(u.nome) === norm(a.usuario_nome));
          empresa = uByName?.empresa || '';
        }
      }
      if (!empresa || empresa === 'null') empresa = '—';

      const usuarioFezAgendamento = usuarioLogadoNome && a.responsavel_nome === usuarioLogadoNome;

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          ${escapeHtml(a.usuario_nome || '')}
          ${usuarioFezAgendamento ? `<span class="cancelar-agendamento" data-id="${a.id}" title="Cancelar agendamento">❌</span>` : ''}
        </td>
        <td>${escapeHtml(empresa)}</td>
        <td>${escapeHtml(a.responsavel_nome || '')}</td>
        <td>${escapeHtml(dataFormatada)}</td>
        <td>${escapeHtml(horaFormatada)}</td>
        <td>${escapeHtml(a.destino || '')}</td>
      `;
      listaAgendamentos.appendChild(tr);
    });

    document.querySelectorAll('.cancelar-agendamento').forEach(btn => {
      btn.addEventListener('click', function () {
        const agendamentoId = this.getAttribute('data-id');
        cancelarAgendamento(agendamentoId);
      });
    });

  } catch (err) {
    console.error('Erro ao carregar agendamentos:', err);
  }
}

async function cancelarAgendamento(agendamentoId) {
  if (!confirm('Tem certeza que deseja cancelar este agendamento?')) return;

  try {
    const headers = { 'Content-Type': 'application/json', ...authHeaders() };
    const res = await fetch(`${API}/agendamentos/${agendamentoId}`, {
      method: 'DELETE',
      headers
    });

    if (res.ok) {
      const result = await res.json().catch(() => ({}));
      setMensagem(result.message || 'Agendamento cancelado com sucesso!', true);
      carregarAgendamentos();
    } else {
      const txt = await res.text();
      try {
        const j = JSON.parse(txt);
        setMensagem(j.error || `Erro ao cancelar agendamento: ${res.status}`, false);
      } catch {
        setMensagem(`Erro ao cancelar agendamento: ${res.status} - ${txt}`, false);
      }
    }
  } catch (err) {
    console.error('Erro ao cancelar agendamento:', err);
    setMensagem('Erro de conexão ao cancelar agendamento.', false);
  }
}


if (usuarioInput) {
  usuarioInput.addEventListener('change', () => {
    const id = getUsuarioIdByRotulo(usuarioInput.value);
    usuarioIdHidden.value = id || '';
    if (!id && usuarioInput.value.trim() !== '') {
      setMensagem('Escolha um Visitante/Fornecedor da lista.', false);
    }
  });

  usuarioInput.addEventListener('input', () => {
    if (!usuarioInput.value) usuarioIdHidden.value = '';
  });
}

if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!usuarioIdHidden.value) {
      usuarioIdHidden.value = getUsuarioIdByRotulo(usuarioInput.value) || '';
    }

    const usuario_id     = usuarioIdHidden.value;
    const responsavel_id = responsavelIdHidden.value;
    const data_agendada  = document.getElementById('data').value;
    const hora_agendada  = document.getElementById('hora').value;
    const destino        = document.getElementById('destino').value;

    if (!usuario_id)     return setMensagem('Usuário inválido. Escolha um da lista.', false);
    if (!responsavel_id) return setMensagem('Responsável não identificado. Faça login novamente.', false);

    const payload = { usuario_id, responsavel_id, data_agendada, hora_agendada, destino };

    try {
      const headers = { 'Content-Type': 'application/json', ...authHeaders() };
      const res = await fetch(`${API}/agendar`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      const result = await res.json().catch(() => ({}));
      if (res.ok) {
        setMensagem(result.message || 'Agendamento realizado com sucesso!', true);

        usuarioInput.value = '';
        usuarioIdHidden.value = '';
        document.getElementById('data').value = '';
        document.getElementById('hora').value = '';
        document.getElementById('destino').value = '';

        carregarAgendamentos();
      } else {
        setMensagem(result.error || 'Erro ao agendar usuário.', false);
      }
    } catch (err) {
      console.error(err);
      setMensagem('Erro ao enviar agendamento.', false);
    }
  });
}

if (btnNovoCadastro) {
  btnNovoCadastro.addEventListener('click', () => {
    window.location.href = '/cadastro.html';
  });
}
if (btnLogout) {
  btnLogout.addEventListener('click', hardLogout);
}

if (filtroTabela) {
  filtroTabela.addEventListener('input', function () {
    const filtro = norm(this.value);
    const linhas = document.querySelectorAll('#listaAgendamentos tr');
    linhas.forEach(linha => {
      const usuario = norm(linha.cells[0]?.textContent || '');
      linha.style.display = usuario.includes(filtro) ? '' : 'none';
    });
  });
}

(async function init() {
  if (!token) {
    window.location.replace('/login.html');
    return;
  }

  bloquearVoltaSeDeslogado();
  configurarFormularioAgendamento();
  await carregarResponsavel();
  await carregarUsuarios();
  await carregarAgendamentos();
})();
