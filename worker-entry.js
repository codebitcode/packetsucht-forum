import legacyWorker from './_worker.js';

const ADMIN_NAME = 'champ';

// IPs, die über diese User-IDs benutzt wurden, gelten in Analytics als "mit dir verknüpft".
// 17 ist bewusst NICHT dabei (Odmis).
const OWN_USER_IDS = new Set([
  2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  18, 19, 20
]);
const OWN_USER_IDS_SQL = Array.from(OWN_USER_IDS).join(',');

function isOwnUserId(id) {
  return OWN_USER_IDS.has(Number(id));
}

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

      const { results: ownIpRows } = await env.DB.prepare(`
        SELECT DISTINCT ip
        FROM stats
        WHERE ip IS NOT NULL
          AND ip <> ''
          AND (
            user_id IN (${OWN_USER_IDS_SQL})
            OR LOWER(path) LIKE '%/admin%'
          )
      `).all();

      // Für gemerkte IPs holen wir die komplette Historie, unabhängig vom
      // aktuell ausgewählten Zeitraum. So verschwinden Favoriten nie.
      const { results: favoriteStatRows } = await env.DB.prepare(`
        SELECT s.id, s.ip, s.country, s.path, s.user_id, s.created_at
        FROM stats s
        INNER JOIN ip_notes n ON n.ip = s.ip
        ORDER BY s.created_at DESC, s.id DESC
      `).all();

      const notes = new Map(noteRows.map(row => [row.ip, row]));
      const devices = new Map(deviceRows.map(row => [row.ip, row]));
      const ownIps = new Set(ownIpRows.map(row => row.ip));

      function classify(item) {
        const userIds = Array.from(new Set((item.user_ids || []).map(id => Number(id))));
        const knownOwnIp = ownIps.has(item.ip);

        return {
          ...item,
          user_ids: userIds,
          known_own_ip: knownOwnIp,
          unknown: !knownOwnIp,
          registered_other: userIds.some(id => !isOwnUserId(id)),
          device: devices.get(item.ip) || null
        };
      }

      // Zuerst die Zeilen des ausgewählten Zeitraums.
      const currentRows = (data.ips || []).map(item => {
        const saved = notes.get(item.ip);
        return classify({
          ...item,
          remembered: Boolean(saved),
          note: saved?.note || '',
          note_updated_at: saved?.updated_at || null
        });
      });

      // Die Kennzahlen oben bleiben reine Zeitraum-Kennzahlen.
      data.unknown_ips = currentRows.filter(item => item.unknown).length;

      // Danach bauen wir für jeden Favoriten eine Allzeit-Zeile.
      const favoriteRows = new Map();
      for (const saved of noteRows) {
        favoriteRows.set(saved.ip, {
          ip: saved.ip,
          country: '??',
          hits: 0,
          first_seen: null,
          last_seen: null,
          user_ids: [],
          paths: [],
          remembered: true,
          note: saved.note || '',
          note_updated_at: saved.updated_at || null
        });
      }

      for (const row of favoriteStatRows) {
        const item = favoriteRows.get(row.ip);
        if (!item) continue;

        item.hits += 1;

        if (item.first_seen == null || row.created_at < item.first_seen) {
          item.first_seen = row.created_at;
        }
        if (item.last_seen == null || row.created_at > item.last_seen) {
          item.last_seen = row.created_at;
          item.country = row.country || item.country;
        }

        if (row.user_id != null) {
          const id = Number(row.user_id);
          if (!item.user_ids.includes(id)) item.user_ids.push(id);
        }

        if (row.path && !item.paths.includes(row.path)) {
          item.paths.push(row.path);
        }
      }

      // Aktuelle und gemerkte Zeilen über die IP zusammenführen:
      // Ein Favorit erscheint also nie doppelt.
      const combined = new Map(currentRows.map(item => [item.ip, item]));

      for (const [ip, historic] of favoriteRows) {
        const current = combined.get(ip);

        if (!current) {
          combined.set(ip, classify(historic));
          continue;
        }

        const firstSeenValues = [current.first_seen, historic.first_seen].filter(v => v != null);
        const lastSeenValues = [current.last_seen, historic.last_seen].filter(v => v != null);

        combined.set(ip, classify({
          ...current,
          country: historic.country && historic.country !== '??' ? historic.country : current.country,
          hits: historic.hits || current.hits,
          first_seen: firstSeenValues.length ? Math.min(...firstSeenValues) : null,
          last_seen: lastSeenValues.length ? Math.max(...lastSeenValues) : null,
          user_ids: Array.from(new Set([
            ...(historic.user_ids || []),
            ...(current.user_ids || [])
          ])),
          paths: Array.from(new Set([
            ...(current.paths || []),
            ...(historic.paths || [])
          ])),
          remembered: true,
          note: historic.note || '',
          note_updated_at: historic.note_updated_at || null
        }));
      }

      // Favoriten oben, danach wie bisher nach letztem Zugriff.
      data.ips = Array.from(combined.values()).sort((a, b) => {
        const favoriteDiff = Number(Boolean(b.remembered)) - Number(Boolean(a.remembered));
        if (favoriteDiff) return favoriteDiff;
        return (b.last_seen || 0) - (a.last_seen || 0);
      });

      return json(data);
    }

    return legacyWorker.fetch(request, env, ctx);
  }
};
