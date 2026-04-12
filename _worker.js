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


async function verifyPassword(password, stored) {
    const enc = new TextEncoder();
    const [saltHex, hashHex] = stored.split(":");

    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(h => parseInt(h, 16)));

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
    const newHashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

    return newHashHex === hashHex;
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

            let password_hash;
            let result;

            try {
                password_hash = await hashPassword(password);

                result = await env.DB.prepare(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)"
                ).bind(username, password_hash).run();
            } catch (e) {
                return new Response("register error: " + e.message, { status: 500 });
            }

            return new Response(JSON.stringify({
                success: true,
                user_id: result.meta?.last_row_id ?? null
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        ///////////Passwort///////////
        //////Login/////////

        if (url.pathname.startsWith("/api/login")) {
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

            const user = await env.DB.prepare(
                "SELECT * FROM users WHERE username = ?"
            ).bind(username).first();

            if (!user) {
                return new Response("invalid login", { status: 401 });
            }

            let ok = false;

            try {
                ok = await verifyPassword(password, user.password_hash);
            } catch (e) {
                return new Response("verify error: " + e.message, { status: 500 });
            }

            if (!ok) {
                return new Response("invalid login", { status: 401 });
            }

            const sessionId = crypto.randomUUID();

            await env.DB.prepare(
                "INSERT INTO sessions (id, user_id) VALUES (?, ?)"
            ).bind(sessionId, user.id).run();

            return new Response(JSON.stringify({
                success: true,
                user: {
                    id: user.id,
                    username: user.username
                }
            }), {
                headers: {
                    "Content-Type": "application/json",
                    "Set-Cookie": `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Lax`
                }
            });
        }


        /////////Logout

        if (url.pathname === "/api/logout") {
            const cookie = request.headers.get("cookie") || "";
            const match = cookie.match(/session_id=([^;]+)/);

            if (match) {
                const sessionId = match[1];

                await env.DB.prepare(
                    "DELETE FROM sessions WHERE id = ?"
                ).bind(sessionId).run();
            }

            return new Response("ok", {
                headers: {
                    "Set-Cookie": "session_id=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                }
            });
        }

        ////////api/me
        // /////// ME (eingeloggt prüfen) ///////

        if (url.pathname.startsWith("/api/me")) {
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

        ////////////threads/////////////////////


        if (url.pathname.startsWith("/api/threads")) {
            if (request.method === "GET") {
           const { results } = await env.DB.prepare(
              "SELECT * FROM threads WHERE id > 1 ORDER BY id DESC"
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

                const { title } = body || {};

                const cookie = request.headers.get("cookie") || "";
                const match = cookie.match(/session_id=([^;]+)/);

                if (!match) {
                    return new Response("not logged in", { status: 401 });
                }

                const session = await env.DB.prepare(
                    "SELECT user_id FROM sessions WHERE id = ?"
                ).bind(match[1]).first();

                if (!session) {
                    return new Response("invalid session", { status: 401 });
                }

                if (!title) {
                    return new Response("missing data", { status: 400 });
                }

                await env.DB.prepare(
                    "INSERT INTO threads (title, user_id) VALUES (?, ?)"
                )
                    .bind(title, session.user_id)
                    .run();

                return new Response(JSON.stringify({ success: true }), {
                    headers: { "Content-Type": "application/json" },
                });
            }

            return new Response("Method not allowed", { status: 405 });
        }


        /////////////////Post

        if (url.pathname.startsWith("/api/posts")) {
            if (request.method === "GET") {
                const threadId = Number(url.searchParams.get("thread_id"));

                if (!threadId) {
                    return new Response("thread_id fehlt", { status: 400 });
                }

               const { results } = await env.DB.prepare(
                  `SELECT posts.*, users.username
                   FROM posts
                   JOIN users ON posts.user_id = users.id
                   WHERE posts.thread_id = ?
                   ORDER BY posts.id ASC`
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

                const { thread_id, content } = body || {};
                const cookie = request.headers.get("cookie") || "";
                const match = cookie.match(/session_id=([^;]+)/);

                if (!match) {
                    return new Response("not logged in", { status: 401 });
                }

                const session = await env.DB.prepare(
                    "SELECT user_id FROM sessions WHERE id = ?"
                ).bind(match[1]).first();

                if (!session) {
                    return new Response("invalid session", { status: 401 });
                }


                if (!thread_id || !content) {
                    return new Response("missing data", { status: 400 });
                }

                await env.DB.prepare(
                    "INSERT INTO posts (thread_id, user_id, content) VALUES (?, ?, ?)"
                )
                    .bind(Number(thread_id), session.user_id, content)
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
