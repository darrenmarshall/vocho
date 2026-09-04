export const config = {
  matcher: ["/((?!_vercel|favicon.ico|images/logo\\.svg).*)"],
};

const COOKIE = "vocho_ok";

function gatePage(wrong) {
  const html = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Vocho</title>
<style>
  html, body { margin: 0; min-height: 100%; background: #fff; color: #191813; }
  body {
    min-height: 100dvh;
    display: grid;
    grid-template-columns: 1fr 1fr;
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    background: #fff;
  }
  .side {
    display: grid;
    place-items: center;
    padding: 2.5rem 1.75rem;
    background: #fff;
  }
  form { width: min(17rem, 100%); }
  .panel {
    display: grid;
    place-items: center;
    background: #100F0C;
  }
  .panel__mark {
    display: block;
    width: 40%;
    height: auto;
    aspect-ratio: 562 / 201;
    background: #fff;
    -webkit-mask: url("/images/logo.svg") center / contain no-repeat;
    mask: url("/images/logo.svg") center / contain no-repeat;
  }
  label {
    display: block;
    font-size: .6875rem;
    font-weight: 500;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: #5A574E;
  }
  input {
    width: 100%;
    margin: .45rem 0 1.2rem;
    padding: .55rem 0;
    border: 0;
    border-bottom: 1px solid rgba(25,24,19,.2);
    background: #fff;
    color: #191813;
    font: inherit;
    font-size: 1rem;
    outline: none;
  }
  input:focus { border-bottom-color: #191813; }
  button {
    font: inherit;
    font-size: .6875rem;
    font-weight: 500;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: #191813;
    background: none;
    border: 0;
    padding: 0;
    cursor: pointer;
  }
  button:hover { opacity: .55; }
  .err {
    margin: .9rem 0 0;
    font-size: .8125rem;
    color: #837F74;
  }
  @media (max-width: 720px) {
    body { grid-template-columns: 1fr; grid-template-rows: 1fr 40vh; }
    .panel { order: 2; }
  }
</style>
<div class="side">
  <form id="gate" autocomplete="on">
    <label for="user">User</label>
    <input id="user" name="username" type="text" autocomplete="username" autocapitalize="off" spellcheck="false" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Enter</button>
    ${wrong ? '<p class="err">Try again.</p>' : ""}
  </form>
</div>
<aside class="panel" aria-hidden="true"><span class="panel__mark"></span></aside>
<script>
(function () {
  var COOKIE = ${JSON.stringify(COOKIE)};
  document.getElementById("gate").addEventListener("submit", async function (e) {
    e.preventDefault();
    var pass = document.getElementById("password").value;
    var buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("vocho|" + pass));
    var hex = Array.from(new Uint8Array(buf)).map(function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
    var secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = COOKIE + "=" + hex + "; Path=/; SameSite=Lax; Max-Age=2592000" + secure;
    location.replace("/");
  });
})();
</script>`;
  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Pragma: "no-cache",
    },
  });
}

async function token(password) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("vocho|" + password)
  );
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function basicPassword(header) {
  if (!header.startsWith("Basic ")) return "";
  try {
    const decoded = atob(header.slice(6));
    return decoded.includes(":") ? decoded.slice(decoded.indexOf(":") + 1) : decoded;
  } catch (_) {
    return "";
  }
}

export default async function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  if (!password) {
    return new Response("Site password is not configured.", { status: 500 });
  }

  const expected = await token(password);
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(new RegExp("(?:^|; )" + COOKIE + "=([^;]+)"));
  const viaCookie = match && match[1] === expected;
  const viaBasic = basicPassword(request.headers.get("authorization") || "") === password;

  if (viaCookie || viaBasic) return;

  const url = new URL(request.url);
  const accept = request.headers.get("accept") || "";
  if (!accept.includes("text/html") && url.pathname !== "/" && !url.pathname.endsWith(".html")) {
    return new Response(null, {
      status: 401,
      headers: { "Cache-Control": "no-store" },
    });
  }

  return gatePage(Boolean(match && match[1]));
}
