export function accessLog(req, res, next) {
  const start = Date.now();
  const ua = req.get("user-agent") || "";
  const ip = req.ip;
  console.log(`[REQ] ${req.method} ${req.originalUrl} | ip=${ip} ua="${ua}"`);
  res.on("finish", () => {
    const ms = Date.now() - start;
    console.log(`[RES] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
}
