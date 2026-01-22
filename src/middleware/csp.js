export function csp(_req, res, next) {
  res.setHeader("Content-Security-Policy", [
    "default-src 'self' data: blob:",
    "connect-src 'self' https: wss: http: ws:",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
  ].join("; "));
  next();
}
