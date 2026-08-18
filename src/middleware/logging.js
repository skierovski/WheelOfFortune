export function accessLog(req, res, next) {
  const start = Date.now();
  const ua = req.get("user-agent") || "";
  const ip = req.ip;
  const safePath = String(req.originalUrl || req.path || "/").split("?")[0];
  console.log(`[REQ] ${req.method} ${safePath} | ip=${ip} ua="${ua.replace(/[\r\n]/g, " ").slice(0, 200)}"`);
  res.on("finish", () => {
    const ms = Date.now() - start;
    console.log(`[RES] ${req.method} ${safePath} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
}
