
const crypto = require("crypto");

exports.handler = async (event) => {
  try {
    const secret = process.env.SESSION_SECRET;

    if (!secret || secret.length < 32) {
      return {
        statusCode: 500,
        body: "Steam login is not configured: SESSION_SECRET is missing."
      };
    }

    const site = "https://zesty-blini-1a4703.netlify.app";
    const callback = `${site}/.netlify/functions/steam-callback`;

    const state = crypto.randomBytes(24).toString("hex");
    const signature = crypto
      .createHmac("sha256", secret)
      .update(state)
      .digest("hex");

    const stateCookie = `${state}.${signature}`;
    const returnTo = `${callback}?state=${state}`;

    const steamUrl = new URL("https://steamcommunity.com/openid/login");
    steamUrl.searchParams.set("openid.ns", "http://specs.openid.net/auth/2.0");
    steamUrl.searchParams.set("openid.mode", "checkid_setup");
    steamUrl.searchParams.set("openid.return_to", returnTo);
    steamUrl.searchParams.set("openid.realm", site);
    steamUrl.searchParams.set(
      "openid.identity",
      "http://specs.openid.net/auth/2.0/identifier_select"
    );
    steamUrl.searchParams.set(
      "openid.claimed_id",
      "http://specs.openid.net/auth/2.0/identifier_select"
    );

    return {
      statusCode: 302,
      headers: {
        Location: steamUrl.toString(),
        "Set-Cookie": `wmd_state=${stateCookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
      },
      body: ""
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: "Could not start Steam login."
    };
  }
};
