/* Load HTML fragments first, then boot the app scripts.
   Must be external JS because CSP in production blocks inline scripts. */
(async function loadAppWithFragments() {
    try {
        const ASSET_VERSION = '20260214-f7';
        const sections = document.querySelectorAll('section[data-fragment]');

        for (const section of sections) {
            const file = section.getAttribute('data-fragment');
            if (!file) continue;
            const response = await fetch('/' + file + '?v=' + encodeURIComponent(ASSET_VERSION), { cache: 'no-store' });
            if (!response.ok) {
                throw new Error('Falha ao carregar fragmento ' + file + ': HTTP ' + response.status);
            }
            const html = await response.text();
            const parsed = new DOMParser().parseFromString(html, 'text/html');
            const bodyHtml = parsed && parsed.body ? parsed.body.innerHTML : '';
            section.innerHTML = bodyHtml && bodyHtml.trim() ? bodyHtml : html;
        }

        await new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'script.js?v=' + encodeURIComponent(ASSET_VERSION);
            script.onload = resolve;
            script.onerror = () => reject(new Error('Falha ao carregar script.js'));
            document.body.appendChild(script);
        });

        const assistant = document.createElement('script');
        assistant.src = 'assistant.js?v=' + encodeURIComponent(ASSET_VERSION);
        document.body.appendChild(assistant);
    } catch (error) {
        console.error('Erro ao carregar a interface:', error);
        const app = document.getElementById('appSection');
        if (app) {
            app.insertAdjacentHTML(
                'afterbegin',
                '<div class="card" style="margin:16px;">Falha ao carregar a interface. Recarregue a pagina.</div>'
            );
        }
    }
})();
