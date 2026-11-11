const form = document.getElementById('login-form');
const button = document.getElementById('btnEntrar');
const message = document.getElementById('mensagem');
const apiBase = window.API_BASE || '';

form.addEventListener('submit', async event => {
  event.preventDefault();
  message.textContent = '';
  button.disabled = true;

  const identifier = document.getElementById('identificador').value.trim();
  const password = document.getElementById('senha').value;

  const payload = identifier.includes('@')
    ? { email: identifier, senha: password }
    : { usuario: identifier, senha: password };

  try {
    const response = await fetch(`${apiBase}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    if (!response.ok) {
      message.textContent = result.error || 'Falha no login';
      message.style.color = 'red';
      return;
    }

    localStorage.setItem('token', result.token);
    localStorage.setItem('usuario_nome', result.usuario.nome);
    localStorage.setItem('usuario_tipo', result.usuario.tipo.toLowerCase());
    localStorage.setItem('usuario_id', result.usuario.id);

    const destinations = {
      colaborador: '/agendamento.html',
      portaria: '/home.html',
      admin: '/gerenciamento.html',
      rh: '/rh.html'
    };

    window.location.href = destinations[result.usuario.tipo.toLowerCase()] || '/home.html';
  } catch {
    message.textContent = 'Não foi possível acessar o servidor local';
    message.style.color = 'red';
  } finally {
    button.disabled = false;
  }
});
