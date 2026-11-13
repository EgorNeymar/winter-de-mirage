
const crypto = require("crypto");

function decodeXml(value) {
    return value
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'");
}

function getTag(xml, tag) {
    const match = xml.match(
        new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "i")
    );

    return match ? decodeXml(match[1].trim()) : null;
}

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

        const [payload, signature] = value.split(".");

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

        const steamId = session.steamId;

        let nickname = null;
        let avatar = null;

        try {
            const response = await fetch(
                `https://steamcommunity.com/profiles/${steamId}/?xml=1`
            );

            if (response.ok) {
                const xml = await response.text();
                nickname = getTag(xml, "steamID");
                avatar = getTag(xml, "avatarFull");
            }
        } catch (error) {
            // Профиль может быть временно недоступен.
        }

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                loggedIn: true,
                steamId,
                nickname,
                avatar,
                profileUrl: `https://steamcommunity.com/profiles/${steamId}`
            })
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: "Session check failed" })
        };
    }
};
