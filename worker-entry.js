import legacyWorker from './_worker.js';

const ADMIN_NAME = 'champ';

async function getLoggedInUser(request, env) {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(/session_id=([^;]+)/);
  if (!match) return null;

  const session = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE id = ?'
  ).bind(match[1]).first();
  if (!session) return null;

  return await env.DB.prepare(
    'SELECT id, username FROM users WHERE id = ?'
  ).bind(session.user_id).first();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function ensureIpNotesTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS ip_notes (
      ip TEXT PRIMARY KEY,
      note TEXT NOT NULL DEFAULT '',
      updated_at INTEGER NOT NULL
    )
  `).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/admin/ip-note' && request.method === 'POST') {
      const user = await getLoggedInUser(request, env);
      if (!user || user.username !== ADMIN_NAME) {
        return new Response('forbidden', { status: 403 });
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return new Response('invalid json', { status: 400 });
      }

      const ip = String(body?.ip || '').trim();
      const note = String(body?.note || '').trim();
      const remembered = body?.remembered !== false;

      if (!ip || ip.length > 128) {
        return new Response('invalid ip', { status: 400 });
      }
      if (note.length > 500) {
        return new Response('note too long', { status: 400 });
      }

      await ensureIpNotesTable(env);

      if (!remembered) {
        await env.DB.prepare('DELETE FROM ip_notes WHERE ip = ?').bind(ip).run();
        return json({ success: true, remembered: false });
      }

      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare(`
        INSERT INTO ip_notes (ip, note, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
          note = excluded.note,
          updated_at = excluded.updated_at
      `).bind(ip, note, now).run();

      return json({ success: true, remembered: true, ip, note, updated_at: now });
    }

    if (url.pathname === '/api/admin/analytics' && request.method === 'GET') {
      const response = await legacyWorker.fetch(request, env, ctx);
      if (!response.ok) return response;

      const data = await response.json();
      await ensureIpNotesTable(env);

      const { results: noteRows } = await env.DB.prepare(`
        SELECT ip, note, updated_at
        FROM ip_notes
        ORDER BY updated_at DESC
      `).all();

      const notes = new Map(noteRows.map(row => [row.ip, row]));
      data.ips = (data.ips || []).map(item => {
        const saved = notes.get(item.ip);
        return {
          ...item,
          remembered: Boolean(saved),
          note: saved?.note || '',
          note_updated_at: saved?.updated_at || null
        };
      });

      return json(data);
    }

    return legacyWorker.fetch(request, env, ctx);
  }
};
