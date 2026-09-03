export const config = {
  matcher: ["/((?!_vercel|favicon.ico).*)"],
};

export default function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  if (!password) {
    return new Response("Site password is not configured.", { status: 500 });
  }

  const header = request.headers.get("authorization") || "";
  if (header.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice(6));
      const pass = decoded.includes(":") ? decoded.slice(decoded.indexOf(":") + 1) : decoded;
      if (pass === password) return;
    } catch (_) {
      /* fall through to 401 */
    }
  }

  return new Response("Password required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Vocho"',
      "Cache-Control": "no-store",
    },
  });
}
