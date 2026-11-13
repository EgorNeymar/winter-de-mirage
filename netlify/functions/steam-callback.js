
const crypto = require("crypto");

function safeEqual(a, b) {
  const first = Buffer.from(a);
  const second = Buffer.from(b);

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

exports.handler = async (event) => {
  try {
    const secret = process.env.SESSION_SECRET;

    if (!secret || secret.length < 32) {
      return { statusCode: 500, body: "Steam login is not configured." };
    }

    const params = event.queryStringParameters || {};
    const state = params.state || "";
    const cookies = event.headers.cookie || event.headers.Cookie || "";

    const stateCookie = cookies
      .split(";")
      .map(item => item.trim())
      .find(item => item.startsWith("wmd_state="));

    if (!stateCookie) {
      return { statusCode: 400, body: "Login session expired. Try again." };
    }

    const cookieValue = decodeURIComponent(stateCookie.slice("wmd_state=".length));
    const [cookieState, cookieSignature] = cookieValue.split(".");

    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(cookieState || "")
      .digest("hex");

    if (
      !state ||
      state !== cookieState ||
      !cookieSignature ||
      !safeEqual(cookieSignature, expectedSignature)
    ) {
      return { statusCode: 400, body: "Invalid login state. Try again." };
    }

    const site = "https://zesty-blini-1a4703.netlify.app";
    const callback = `${site}/.netlify/functions/steam-callback`;
    const expectedReturnTo = `${callback}?state=${state}`;

    if (params["openid.return_to"] !== expectedReturnTo) {
      return { statusCode: 400, body: "Invalid Steam callback." };
    }

    const claimedId = params["openid.claimed_id"] || "";
    const identity = params["openid.identity"] || "";
    const match = claimedId.match(
      /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/
    );

    if (!match || identity !== claimedId) {
      return { statusCode: 400, body: "Invalid Steam account." };
    }

    const steamId = match[1];
    const verification = new URLSearchParams();

    for (const [key, value] of Object.entries(params)) {
      if (key.startsWith("openid.")) {
        verification.set(key, value);
      }
    }

    verification.set("openid.mode", "check_authentication");

    const response = await fetch("https://steamcommunity.com/openid/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: verification.toString()
    });

    const result = await response.text();

    if (!response.ok || !/\bis_valid:true\b/.test(result)) {
      return { statusCode: 401, body: "Steam could not verify the login." };
    }

    const payload = Buffer.from(JSON.stringify({
      steamId,
      issuedAt: Date.now()
    })).toString("base64url");

    const sessionSignature = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    const sessionCookie = `${payload}.${sessionSignature}`;

    return {
      statusCode: 302,
      headers: {
       "Set-Cookie": `wmd_session=${sessionCookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
"Set-Cookie-2": "wmd_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        ]
      },
      body: ""
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: "Steam login failed. Please try again."
    };
  }
};
