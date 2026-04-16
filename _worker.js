const ADMIN_NAME = "champ";
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


//////////Admin


async function getLoggedInUser(request, env) {
    const cookie = request.headers.get("cookie") || "";
    const match = cookie.match(/session_id=([^;]+)/);

    if (!match) return null;

    const session = await env.DB.prepare(
        "SELECT user_id FROM sessions WHERE id = ?"
    ).bind(match[1]).first();

    if (!session) return null;

    const user = await env.DB.prepare(
        "SELECT id, username FROM users WHERE id = ?"
    ).bind(session.user_id).first();

    return user || null;
}





export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (
            request.method === "GET" &&
            !url.pathname.startsWith("/api") &&
            !url.pathname.startsWith("/Bilder/") &&
            !url.pathname.includes(".")
        ) {
            const rawIp = request.headers.get("CF-Connecting-IP") || "";
            const ip = await sha256(rawIp);
            const country = request.cf?.country || "??";
            const path = url.pathname + url.search;

            const user = await getLoggedInUser(request, env);
            const userId = user ? user.id : null;

            await env.DB.prepare(`
                INSERT INTO stats (ip, country, path, user_id, created_at)
                VALUES (?, ?, ?, ?, ?)
            `).bind(ip, country, path, userId, Date.now()).run();
        }

        if (url.pathname.startsWith("/api/image/")) {
            const fileName = decodeURIComponent(url.pathname.replace("/api/image/", ""));
            const object = await env.IMAGES_BUCKET.get(fileName);

            if (!object) {
                return new Response("Not found", { status: 404 });
            }

            return new Response(object.body, {
                headers: {
                    "Content-Type": object.httpMetadata?.contentType || "image/jpeg"
                }
            });
        }


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

            await env.DB.prepare(
                "DELETE FROM sessions WHERE created_at < datetime('now', '-7 days')"
            ).run();

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
                    "Set-Cookie": `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`
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

            const isAdmin = user.username === ADMIN_NAME;

            return new Response(JSON.stringify({
                loggedIn: true,
                user,
                isAdmin
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }


        /////////////Admin

        if (url.pathname === "/api/images" && request.method === "GET") {
            const user = await getLoggedInUser(request, env);

            if (!user || user.username !== ADMIN_NAME) {
                return new Response("forbidden", { status: 403 });
            }

            const status = url.searchParams.get("status") || "pending";

            const { results } = await env.DB.prepare(
                "SELECT * FROM images WHERE status = ? ORDER BY id DESC"
            ).bind(status).all();

            return new Response(JSON.stringify(results), {
                headers: { "Content-Type": "application/json" }
            });
        }

        if (url.pathname === "/api/images/approve" && request.method === "POST") {
            const user = await getLoggedInUser(request, env);

            if (!user || user.username !== ADMIN_NAME) {
                return new Response("forbidden", { status: 403 });
            }

            let body;

            try {
                body = await request.json();
            } catch {
                return new Response("invalid json", { status: 400 });
            }

            const { id } = body || {};

            if (!id) {
                return new Response("missing id", { status: 400 });
            }

            await env.DB.prepare(
                "UPDATE images SET status = 'approved' WHERE id = ?"
            ).bind(id).run();

            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        if (url.pathname === "/api/images/reject" && request.method === "POST") {
            const user = await getLoggedInUser(request, env);

            if (!user || user.username !== ADMIN_NAME) {
                return new Response("forbidden", { status: 403 });
            }

            let body;
            try {
                body = await request.json();
            } catch {
                return new Response("invalid json", { status: 400 });
            }

            const { id } = body || {};
            if (!id) {
                return new Response("missing id", { status: 400 });
            }

            const image = await env.DB.prepare(
                "SELECT * FROM images WHERE id = ?"
            ).bind(id).first();

            if (!image) {
                return new Response("image not found", { status: 404 });
            }

            await env.DB.prepare(
                "DELETE FROM posts WHERE image = ?"
            ).bind(image.filename).run();

            await env.DB.prepare(
                "UPDATE images SET status = 'rejected' WHERE id = ?"
            ).bind(id).run();

            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        if (url.pathname === "/api/images/delete" && request.method === "POST") {
            const user = await getLoggedInUser(request, env);

            if (!user || user.username !== ADMIN_NAME) {
                return new Response("forbidden", { status: 403 });
            }

            let body;
            try {
                body = await request.json();
            } catch {
                return new Response("invalid json", { status: 400 });
            }

            const { id } = body || {};
            if (!id) {
                return new Response("missing id", { status: 400 });
            }

            const image = await env.DB.prepare(
                "SELECT * FROM images WHERE id = ?"
            ).bind(id).first();

            if (!image) {
                return new Response("image not found", { status: 404 });
            }

            if (image.filename) {
                await env.IMAGES_BUCKET.delete(image.filename);
            }

            await env.DB.prepare(
                "DELETE FROM images WHERE id = ?"
            ).bind(id).run();

            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        /////////////Threads/Delite

        if (url.pathname === "/api/threads/delete" && request.method === "POST") {
            const user = await getLoggedInUser(request, env);

            if (!user || user.username !== ADMIN_NAME) {
                return new Response("forbidden", { status: 403 });
            }

            let body;
            try {
                body = await request.json();
            } catch {
                return new Response("invalid json", { status: 400 });
            }

            const { id } = body || {};
            if (!id) {
                return new Response("missing id", { status: 400 });
            }

            const thread = await env.DB.prepare(
                "SELECT * FROM threads WHERE id = ?"
            ).bind(id).first();

            if (!thread) {
                return new Response("thread not found", { status: 404 });
            }

            const { results: images } = await env.DB.prepare(
                "SELECT * FROM images WHERE thread_id = ?"
            ).bind(id).all();

            for (const image of images) {
                if (image.filename) {
                    await env.IMAGES_BUCKET.delete(image.filename);
                }
            }

            await env.DB.prepare(
                "DELETE FROM images WHERE thread_id = ?"
            ).bind(id).run();

            await env.DB.prepare(
                "DELETE FROM posts WHERE thread_id = ?"
            ).bind(id).run();

            await env.DB.prepare(
                "DELETE FROM threads WHERE id = ?"
            ).bind(id).run();

            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        ////////////threads/////////////////////


        if (url.pathname.startsWith("/api/threads")) {
            if (request.method === "GET") {
                const { results } = await env.DB.prepare(
                    "SELECT * FROM threads WHERE id > 2 ORDER BY id DESC"
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


        /////////////////PostDe;ite


        if (url.pathname === "/api/posts/delete" && request.method === "POST") {
            const user = await getLoggedInUser(request, env);

            if (!user || user.username !== ADMIN_NAME) {
                return new Response("forbidden", { status: 403 });
            }

            let body;
            try {
                body = await request.json();
            } catch {
                return new Response("invalid json", { status: 400 });
            }

            const { id } = body || {};
            if (!id) {
                return new Response("missing id", { status: 400 });
            }

            const post = await env.DB.prepare(
                "SELECT * FROM posts WHERE id = ?"
            ).bind(id).first();

            if (!post) {
                return new Response("post not found", { status: 404 });
            }

            if (post.image) {
                const image = await env.DB.prepare(
                    "SELECT * FROM images WHERE filename = ?"
                ).bind(post.image).first();

                if (image) {
                    if (image.filename) {
                        await env.IMAGES_BUCKET.delete(image.filename);
                    }

                    await env.DB.prepare(
                        "DELETE FROM images WHERE id = ?"
                    ).bind(image.id).run();
                }
            }

            await env.DB.prepare(
                "DELETE FROM posts WHERE id = ?"
            ).bind(id).run();

            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        /////////////////Post

        if (url.pathname.startsWith("/api/posts")) {
            if (request.method === "GET") {
                const threadId = Number(url.searchParams.get("thread_id"));

                if (!threadId) {
                    return new Response("thread_id fehlt", { status: 400 });
                }

                const { results } = await env.DB.prepare(
                    `SELECT posts.*, users.username, images.status
FROM posts
LEFT JOIN users ON posts.user_id = users.id
LEFT JOIN images ON images.filename = posts.image
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

                const { thread_id, content, image } = body || {};
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


                if (!thread_id || (!content && !image)) {
                    return new Response("missing data", { status: 400 });
                }

                await env.DB.prepare(
                    "INSERT INTO posts (thread_id, user_id, content, image) VALUES (?, ?, ?, ?)"
                )
                    .bind(Number(thread_id), session.user_id, content, image || null)
                    .run();

                return new Response(JSON.stringify({ success: true }), {
                    headers: { "Content-Type": "application/json" },
                });
            }

            return new Response("Method not allowed", { status: 405 });
        }


        //////////BildUploud

        if (url.pathname === "/api/upload") {
            if (request.method !== "POST") {
                return new Response("Method not allowed", { status: 405 });
            }

            try {
                const user = await getLoggedInUser(request, env);

                if (!user) {
                    return new Response("not logged in", { status: 401 });
                }

                const formData = await request.formData();
                const file = formData.get("file");
                const threadId = formData.get("thread_id");

                if (!file || typeof file === "string") {
                    return new Response("No file", { status: 400 });
                }

                const fileName = Date.now() + "-" + file.name;
                const arrayBuffer = await file.arrayBuffer();
                const imageUrl = "/api/image/" + encodeURIComponent(fileName);

                await env.IMAGES_BUCKET.put(fileName, arrayBuffer, {
                    httpMetadata: {
                        contentType: file.type || "application/octet-stream"
                    }
                });

                await env.DB.prepare(
                    "INSERT INTO images (filename, status, user_id, thread_id, image_url) VALUES (?, ?, ?, ?, ?)"
                ).bind(fileName, "pending", user.id, Number(threadId), imageUrl).run();
                return new Response(JSON.stringify({
                    success: true,
                    filename: fileName
                }), {
                    headers: { "Content-Type": "application/json" }
                });
            } catch (e) {
                return new Response("UPLOAD ERROR: " + e.message, { status: 500 });
            }
        }

        return env.ASSETS.fetch(request);
    },
};
async function sha256(text) {
    const enc = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", enc);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}
