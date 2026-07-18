// aitit-sync — Cloudflare Worker backing cloud sync for the aitit Hyrox training dashboard.
// GET /sync  -> returns the stored dashboard JSON (or null)
// POST /sync -> stores the request body as the dashboard JSON
// Both require header X-Sync-Secret to match the SYNC_SECRET secret.

const ALLOWED_ORIGIN = 'https://daviddamjakob-claude.github.io';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Sync-Secret',
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);
    if (url.pathname !== '/sync') {
      return new Response('Not found', { status: 404, headers: cors });
    }

    const secret = request.headers.get('X-Sync-Secret');
    if (!secret || secret !== env.SYNC_SECRET) {
      return new Response('Unauthorized', { status: 401, headers: cors });
    }

    if (request.method === 'GET') {
      const data = await env.AITIT_SYNC_KV.get('dashboard');
      return new Response(data || 'null', {
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'POST') {
      const body = await request.text();
      try {
        JSON.parse(body);
      } catch {
        return new Response('Invalid JSON', { status: 400, headers: cors });
      }
      await env.AITIT_SYNC_KV.put('dashboard', body);
      return new Response('{"ok":true}', {
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    return new Response('Method not allowed', { status: 405, headers: cors });
  },
};
