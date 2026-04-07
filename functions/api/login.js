export async function onRequest(context) {
  const db = context.env.DB;

  if (context.request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const { username, password } = await context.request.json();

  const { results } = await db.prepare(
    "SELECT * FROM users WHERE username = ? AND password = ?"
  ).bind(username, password).all();

  if (results.length === 0) {
    return Response.json({ message: "invalid" }, { status: 401 });
  }

  return Response.json({ message: "ok" });
}