export default {
  async fetch(request, env) {
    const url = new URL(request.url);

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
