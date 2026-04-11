export async function onRequest(context) {
  const db = context.env.DB;
  const url = new URL(context.request.url);

  try {
    if (context.request.method === "GET") {
      const threadId = url.searchParams.get("thread_id");

      const { results } = await db.prepare(
        "SELECT * FROM posts WHERE thread_id = ? ORDER BY id ASC"
      ).bind(threadId).all();

      return Response.json(results);
    }

    if (context.request.method === "POST") {
      const body = await context.request.json();
      const { thread_id, user_id, content } = body;

      const result = await db.prepare(
        "INSERT INTO posts (thread_id, user_id, content) VALUES (?, ?, ?)"
      ).bind(Number(thread_id), user_id || 1, content).run();

      return Response.json({
        success: true,
        result: result
      });
    }

    return new Response("Method not allowed", { status: 405 });
  } catch (err) {
    return new Response("DB Fehler: " + err.message, { status: 500 });
  }
}
