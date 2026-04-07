export async function onRequest(context) {
  const db = context.env.DB;

  if (context.request.method === "GET") {
    const { results } = await db.prepare("SELECT * FROM threads ORDER BY id DESC").all();
    return Response.json(results);
  }

  if (context.request.method === "POST") {
    const body = await context.request.json();
    const { title, user_id } = body;

    await db.prepare(
      "INSERT INTO threads (title, user_id) VALUES (?, ?)"
    ).bind(title, user_id).run();

    return Response.json({ success: true });
  }
}