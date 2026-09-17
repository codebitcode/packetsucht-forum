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

async function ensureVisitorDevicesTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS visitor_devices (
      ip TEXT PRIMARY KEY,
      os TEXT NOT NULL DEFAULT '',
      browser TEXT NOT NULL DEFAULT '',
      language TEXT NOT NULL DEFAULT '',
      screen TEXT NOT NULL DEFAULT '',
      viewport TEXT NOT NULL DEFAULT '',
      timezone TEXT NOT NULL DEFAULT '',
      device_type TEXT NOT NULL DEFAULT '',
      platform TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      updated_at INTEGER NOT NULL
    )
  `).run();
}

function detectOS(userAgent, platform = '') {
  const text = `${userAgent} ${platform}`;
  if (/iPad|iPhone|iPod/i.test(text)) return 'iOS/iPadOS';
  if (/Android/i.test(text)) return 'Android';
  if (/Windows/i.test(text)) return 'Windows';
  if (/CrOS/i.test(text)) return 'Chrome OS';
  if (/Mac/i.test(text)) return 'macOS';
  if (/Linux/i.test(text)) return 'Linux';
  return platform || 'Unbekannt';
}

function detectBrowser(userAgent) {
  if (/Edg\//i.test(userAgent)) return 'Edge';
  if (/OPR\//i.test(userAgent) || /Opera/i.test(userAgent)) return 'Opera';
  if (/Firefox\//i.test(userAgent)) return 'Firefox';
  if (/Chrome\//i.test(userAgent) || /CriOS\//i.test(userAgent)) return 'Chrome';
  if (/Safari\//i.test(userAgent) && !/Chrome|CriOS|Edg|OPR/i.test(userAgent)) return 'Safari';
  return 'Unbekannt';
}

function detectDeviceType(userAgent) {
  if (/iPad|Tablet/i.test(userAgent)) return 'Tablet';
  if (/Mobi|Android|iPhone|iPod/i.test(userAgent)) return 'Handy';
  return 'Desktop';
}

async function saveVisitorDevice(request, env, client = {}) {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  if (!ip) return;

  const userAgent = String(client?.userAgent || request.headers.get('User-Agent') || '').slice(0, 1200);
  const platform = String(client?.platform || '').slice(0, 120);
  const language = String(
    client?.language || (request.headers.get('Accept-Language') || '').split(',')[0] || ''
  ).slice(0, 80);

  const os = String(client?.os || detectOS(userAgent, platform)).slice(0, 80);
  const browser = String(client?.browser || detectBrowser(userAgent)).slice(0, 80);
  const screen = String(client?.screen || '').slice(0, 80);
  const viewport = String(client?.viewport || '').slice(0, 80);
  const timezone = String(client?.timezone || '').slice(0, 120);
  const deviceType = String(client?.deviceType || detectDeviceType(userAgent)).slice(0, 80);
  const now = Math.floor(Date.now() / 1000);

  await ensureVisitorDevicesTable(env);
  await env.DB.prepare(`
    INSERT INTO visitor_devices (
      ip, os, browser, language, screen, viewport, timezone,
      device_type, platform, user_agent, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      os = excluded.os,
      browser = excluded.browser,
      language = excluded.language,
      screen = excluded.screen,
      viewport = excluded.viewport,
      timezone = excluded.timezone,
      device_type = excluded.device_type,
      platform = excluded.platform,
      user_agent = excluded.user_agent,
      updated_at = excluded.updated_at
  `).bind(
    ip, os, browser, language, screen, viewport, timezone,
    deviceType, platform, userAgent, now
  ).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/track-page' && request.method === 'POST') {
      try {
        const clone = request.clone();
        const body = await clone.json();
        await saveVisitorDevice(request, env, body?.client || {});
      } catch (_) {
        try {
          await saveVisitorDevice(request, env, {});
        } catch (_) {}
      }

      return legacyWorker.fetch(request, env, ctx);
    }

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
      await ensureVisitorDevicesTable(env);

      const { results: noteRows } = await env.DB.prepare(`
        SELECT ip, note, updated_at
        FROM ip_notes
        ORDER BY updated_at DESC
      `).all();

      const { results: deviceRows } = await env.DB.prepare(`
        SELECT ip, os, browser, language, screen, viewport, timezone,
               device_type, platform, updated_at
        FROM visitor_devices
      `).all();

      const notes = new Map(noteRows.map(row => [row.ip, row]));
      const devices = new Map(deviceRows.map(row => [row.ip, row]));

      data.ips = (data.ips || []).map(item => {
        const saved = notes.get(item.ip);
        const device = devices.get(item.ip) || null;
        return {
          ...item,
          remembered: Boolean(saved),
          note: saved?.note || '',
          note_updated_at: saved?.updated_at || null,
          device
        };
      });

      return json(data);
    }

    return legacyWorker.fetch(request, env, ctx);
  }
};
