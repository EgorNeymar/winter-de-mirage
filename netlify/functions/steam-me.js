
const crypto = require("crypto");

exports.handler = async (event) => {
    try {
        const secret = process.env.SESSION_SECRET;

        if (!secret || secret.length < 32) {
            return {
                statusCode: 500,
                body: JSON.stringify({ error: "Server configuration error" })
            };
        }

        const cookies = event.headers.cookie ||
            event.headers.Cookie || "";

        const sessionCookie = cookies
            .split(";")
            .map(item => item.trim())
            .find(item => item.startsWith("wmd_session="));

        if (!sessionCookie) {
            return {
                statusCode: 401,
                body: JSON.stringify({ loggedIn: false })
            };
        }

        const value = decodeURIComponent(
            sessionCookie.slice("wmd_session=".length)
        );

        const parts = value.split(".");
        const payload = parts[0];
        const signature = parts[1];

        if (!payload || !signature) {
            return {
                statusCode: 401,
                body: JSON.stringify({ loggedIn: false })
            };
        }

        const expected = crypto
            .createHmac("sha256", secret)
            .update(payload)
            .digest("base64url");

        const first = Buffer.from(signature);
        const second = Buffer.from(expected);

        if (
            first.length !== second.length ||
            !crypto.timingSafeEqual(first, second)
        ) {
            return {
                statusCode: 401,
                body: JSON.stringify({ loggedIn: false })
            };
        }

        const session = JSON.parse(
            Buffer.from(payload, "base64url").toString("utf8")
        );

        if (
            !session.steamId ||
            !session.issuedAt ||
            Date.now() - session.issuedAt > 604800000
        ) {
            return {
                statusCode: 401,
                body: JSON.stringify({ loggedIn: false })
            };
        }

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                loggedIn: true,
                steamId: session.steamId
            })
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: "Session check failed" })
        };
    }
};

