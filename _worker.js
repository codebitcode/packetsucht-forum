export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/threads") {
      if (request.method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT * FROM threads ORDER BY id DESC"
        ).all();

        return new Response(JSON.stringify(results), {
          headers: { "Content-Type": "application/json" },
        });
      }

      if (request.method === "POST") {
        const body = await request.json();
        const { title, user_id } = body;

        await env.DB.prepare(
          "INSERT INTO threads (title, user_id) VALUES (?, ?)"
        )
          .bind(title, user_id)
          .run();

        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    return env.ASSETS.fetch(request);
  },
};
