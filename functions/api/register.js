export async function onRequest(context) {
  const db = context.env.DB;

  if (context.request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const { username, password } = await context.request.json();

  try {
    await db.prepare(
      "INSERT INTO users (username, password) VALUES (?, ?)"
    ).bind(username, password).run();

    return Response.json({ message: "ok" });
  } catch (e) {
    return Response.json({ message: "user exists" }, { status: 400 });
  }
}