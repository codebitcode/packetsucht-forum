export async function onRequest(context) {
  try {
    const db = context.env.DB;
    const url = new URL(context.request.url);

    if (context.request.method === "GET") {
      const threadId = Number(url.searchParams.get("thread_id"));

      if (!threadId) {
        return new Response("thread_id fehlt oder ungültig", { status: 400 });
      }

      const { results } = await db
        .prepare("SELECT * FROM posts WHERE thread_id = ? ORDER BY id ASC")
        .bind(threadId)
        .all();

      return Response.json(results);
    }

    if (context.request.method === "POST") {
      const body = await context.request.json();
      const { thread_id, user_id, content } = body;

      if (!thread_id || !content) {
        return new Response("thread_id oder content fehlt", { status: 400 });
      }

      const result = await db
        .prepare("INSERT INTO posts (thread_id, user_id, content) VALUES (?, ?, ?)")
        .bind(Number(thread_id), Number(user_id) || 1, content)
        .run();

      return Response.json({
        success: true,
        result
      });
    }

    return new Response("Method not allowed", { status: 405 });
  } catch (err) {
    return new Response("DB Fehler: " + err.message, { status: 500 });
  }
}
