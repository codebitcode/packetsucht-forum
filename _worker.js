async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  const hashArray = Array.from(new Uint8Array(bits));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, "0")).join("");
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  return `${saltHex}:${hashHex}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    
    ///////////Passwort///////////

    
if (url.pathname.startsWith("/api/register")) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return new Response("invalid json", { status: 400 });
  }

  const { username, password } = body || {};

  if (!username || !password) {
    return new Response("missing data", { status: 400 });
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE username = ?"
  ).bind(username).first();

  if (existing) {
    return new Response("username exists", { status: 400 });
  }

  const password_hash = await hashPassword(password);

  const result = await env.DB.prepare(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)"
  ).bind(username, password_hash).run();

  return new Response(JSON.stringify({
    success: true,
    user_id: result.meta.last_row_id
  }), {
    headers: { "Content-Type": "application/json" }
  });
}

    ///////////Passwort///////////



    

    if (url.pathname.startsWith("/api/threads")) {
      if (request.method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT * FROM threads ORDER BY id DESC"
        ).all();

        return new Response(JSON.stringify(results), {
          headers: { "Content-Type": "application/json" },
        });
      }

      if (request.method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch (e) {
          return new Response("invalid json", { status: 400 });
        }

        const { title, user_id } = body || {};

        if (!title || !user_id) {
          return new Response("missing data", { status: 400 });
        }

        await env.DB.prepare(
          "INSERT INTO threads (title, user_id) VALUES (?, ?)"
        )
          .bind(title, user_id)
          .run();

        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response("Method not allowed", { status: 405 });
    }

    if (url.pathname.startsWith("/api/posts")) {
      if (request.method === "GET") {
        const threadId = Number(url.searchParams.get("thread_id"));

        if (!threadId) {
          return new Response("thread_id fehlt", { status: 400 });
        }

        const { results } = await env.DB.prepare(
          "SELECT * FROM posts WHERE thread_id = ? ORDER BY id ASC"
        ).bind(threadId).all();

        return new Response(JSON.stringify(results), {
          headers: { "Content-Type": "application/json" },
        });
      }

      if (request.method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch (e) {
          return new Response("invalid json", { status: 400 });
        }

        const { thread_id, user_id, content } = body || {};

        if (!thread_id || !content) {
          return new Response("missing data", { status: 400 });
        }

        await env.DB.prepare(
          "INSERT INTO posts (thread_id, user_id, content) VALUES (?, ?, ?)"
        )
          .bind(Number(thread_id), Number(user_id) || 1, content)
          .run();

        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response("Method not allowed", { status: 405 });
    }

    return env.ASSETS.fetch(request);
  },
};
