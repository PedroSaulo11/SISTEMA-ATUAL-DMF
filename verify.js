function getApiBase() {
  if (!window.location || !window.location.origin || window.location.origin === 'null') {
    return 'http://localhost:3001';
  }
  return window.location.origin;
}

function setResult(message, ok) {
  const el = document.getElementById('verifyResult');
  if (!el) return;
  el.textContent = message;
  el.classList.remove('ok', 'error');
  el.classList.add(ok ? 'ok' : 'error');
}

async function verifySignature(id) {
  if (!id) return;
  try {
    const response = await fetch(`${getApiBase()}/api/public/signatures/${encodeURIComponent(id)}`, {
      cache: 'no-store'
    });
    if (!response.ok) {
      setResult('Assinatura inválida.', false);
      return;
    }
    const data = await response.json();
    if (!data.valid) {
      setResult('Assinatura inválida.', false);
      return;
    }
    const date = data.dataISO ? new Date(data.dataISO).toLocaleString('pt-BR') : '-';
    const extra = data.chainValid ? 'Assinatura válida (cadeia íntegra).' : 'Assinatura válida, porém cadeia inconsistente.';
    setResult(`Assinado por ${data.nome || '-'} em ${date}. ${extra}`, true);
  } catch (_) {
    setResult('Falha ao verificar assinatura.', false);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('signatureIdInput');
  const button = document.getElementById('btnVerifySignature');
  if (button) {
    button.addEventListener('click', () => {
      verifySignature(input?.value?.trim());
    });
  }
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id');
  if (id && input) {
    input.value = id;
    verifySignature(id);
  }
});
