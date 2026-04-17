if (url.pathname === "/api/track-page") {
    if (request.method !== "POST") {
        return new Response("track-page ok", { status: 200 });
    }

    try {
        const body = await request.json();

        const ip = request.headers.get("CF-Connecting-IP") || "";
        const country = request.cf?.country || "??";
        const path = body?.path || "";
        const user = await getLoggedInUser(request, env);
        const userId = user ? user.id : null;

        await env.DB.prepare(`
            INSERT INTO stats (ip, country, path, user_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).bind(ip, country, path, userId, Date.now()).run();

        return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
        });
    } catch (e) {
        return new Response("track error: " + e.message, { status: 500 });
    }
}
