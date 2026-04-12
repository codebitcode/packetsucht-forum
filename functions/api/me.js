if (url.pathname === "/api/me") {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/session_id=([^;]+)/);

  if (!match) {
    return new Response(JSON.stringify({ loggedIn: false }), {
      headers: { "Content-Type": "application/json" }
    });
  }

  const sessionId = match[1];

  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE id = ?"
  ).bind(sessionId).first();

  if (!session) {
    return new Response(JSON.stringify({ loggedIn: false }), {
      headers: { "Content-Type": "application/json" }
    });
  }

  const user = await env.DB.prepare(
    "SELECT id, username FROM users WHERE id = ?"
  ).bind(session.user_id).first();

  return new Response(JSON.stringify({
    loggedIn: true,
    user
  }), {
    headers: { "Content-Type": "application/json" }
  });
}
