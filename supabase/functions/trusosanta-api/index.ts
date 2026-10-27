// No third-party packages; database credentials stay inside Supabase.
const routeActions: Record<string, string> = {
  'GET /api/status': 'status', 'GET /api/me': 'me',
  'POST /api/entries': 'create', 'PATCH /api/me': 'edit', 'DELETE /api/me': 'delete',
};
const json = (body: unknown, status: number, headers: HeadersInit) => new Response(JSON.stringify(body), {
  status, headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, private', 'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff' },
});

Deno.serve(async (request: Request) => {
  const allowedOrigin = Deno.env.get('ALLOWED_ORIGIN');
  const origin = request.headers.get('Origin');
  const cors = { 'Access-Control-Allow-Origin': allowedOrigin || '',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type, x-participant-key', 'Vary': 'Origin' };
  if (!allowedOrigin) return json({ error: 'Регистрация ещё не настроена.' }, 503, {});
  if (origin && origin !== allowedOrigin) return json({ error: 'Запрос с другого сайта запрещён.' }, 403, {});
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const match = new URL(request.url).pathname.match(/\/api\/(status|me|entries)$/);
  const action = match ? routeActions[`${request.method} /api/${match[1]}`] : undefined;
  if (!action) return json({ error: 'Страница не найдена.' }, 404, cors);
  let digest: string | null = null;
  if (action !== 'status') {
    const key = request.headers.get('x-participant-key') || '';
    if (!/^[a-f0-9]{64}$/.test(key)) return json({ error: 'Нужна личная секретная ссылка.' }, 401, cors);
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
    digest = Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  }
  let data: Record<string, unknown> = {};
  if (action === 'create' || action === 'edit') {
    if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json'))
      return json({ error: 'Ожидается JSON.' }, 415, cors);
    // Bound actual bytes, including requests without Content-Length.
    const reader = request.body?.getReader();
    if (!reader) return json({ error: 'Пустая заявка.' }, 400, cors);
    const chunks: Uint8Array[] = []; let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        total += value.length;
        if (total > 4096) { await reader.cancel(); return json({ error: 'Слишком большой запрос.' }, 413, cors); }
        chunks.push(value);
      }
      const combined = new Uint8Array(total); let pos = 0;
      for (const chunk of chunks) { combined.set(chunk, pos); pos += chunk.length; }
      data = JSON.parse(new TextDecoder().decode(combined));
      if (!data || Array.isArray(data) || typeof data !== 'object'
          || typeof data.name !== 'string' || typeof data.size !== 'string') throw new Error();
    } catch { return json({ error: 'Нужны имя и размер.' }, 400, cors); }
  }
  const url = Deno.env.get('SUPABASE_URL');
  const secret = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!url || !secret) return json({ error: 'Регистрация ещё не настроена.' }, 503, cors);
  try {
    const response = await fetch(`${url}/rest/v1/rpc/trusosanta_request`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'apikey': secret, 'Authorization': `Bearer ${secret}` },
      body: JSON.stringify({ p_action: action, p_key_hash: digest, p_name: data.name ?? null, p_size: data.size ?? null }),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return json({ error: 'Хранилище временно недоступно. Попробуй ещё раз.' }, 503, cors);
    const result = await response.json();
    if (result.error) return json({ error: result.error }, result.code || 400, cors);
    return json(result, 200, cors);
  } catch { return json({ error: 'Хранилище временно недоступно. Попробуй ещё раз.' }, 503, cors); }
});
