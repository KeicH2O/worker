/**
 * Deno Deploy — Microsoft API Proxy
 *
 * Принимает POST { url, headers } от Cloudflare Worker,
 * делает запрос к Microsoft от своего IP и возвращает text ответа.
 *
 * Environment Variables (Deno Deploy → Settings):
 *   PROXY_SECRET — тот же секрет что в wrangler secret put PROXY_SECRET
 *
 * ВАЖНО: куки (Set-Cookie) из ответов Microsoft НЕ пробрасываются обратно
 * в воркер — они используются только при прямых запросах.
 * Прокси — fallback для обхода блокировки IP, не для управления сессией.
 */

// Меньше чем CF Worker timeout (30s) с запасом
const TIMEOUT_MS = 20_000;

// Разрешённые домены Microsoft — защита от SSRF
const ALLOWED_DOMAINS = [
  "www.microsoft.com",
  "vlscppe.microsoft.com",
  "ov-df.microsoft.com",
  "software-download.microsoft.com",
  "software-static.download.prss.microsoft.com",
  "officecdn.microsoft.com",
  "go.microsoft.com",
  "aka.ms",
];

function isAllowedUrl(url: string): boolean {
  try {
    const { hostname } = new URL(url);
    return ALLOWED_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d));
  } catch {
    return false;
  }
}

async function handler(req: Request): Promise<Response> {

  // ── Healthcheck ──
  if (req.method === "GET") {
    return new Response(
      JSON.stringify({
        status:    "OK",
        service:   "Microsoft API Proxy",
        uptime_s:  (performance.now() / 1000).toFixed(2),
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

  // ── Метод ──
  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method Not Allowed" }),
      { status: 405, headers: { "Content-Type": "application/json", "Allow": "GET, POST" } }
    );
  }

  // ── Секрет ──
  const expectedSecret = Deno.env.get("PROXY_SECRET");
  if (!expectedSecret) {
    console.error("[proxy] PROXY_SECRET not set");
    return new Response(
      JSON.stringify({ error: "Server configuration error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  const secret = req.headers.get("x-proxy-secret");
  if (!secret || secret !== expectedSecret) {
    const ip = req.headers.get("cf-connecting-ip") ||
               req.headers.get("x-forwarded-for") ||
               "unknown";
    console.error("[proxy] unauthorized from:", ip);
    return new Response(
      JSON.stringify({ error: "Unauthorized" }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }

  // ── Парсинг тела ──
  let body: { url?: string; headers?: Record<string, string> };
  try {
    body = await req.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const { url, headers = {} } = body;

  if (!url || typeof url !== "string") {
    return new Response(
      JSON.stringify({ error: "Missing 'url'" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // ── SSRF защита — только домены Microsoft ──
  if (!isAllowedUrl(url)) {
    console.error("[proxy] blocked non-Microsoft URL:", url);
    return new Response(
      JSON.stringify({ error: "URL not allowed" }),
      { status: 403, headers: { "Content-Type": "application/json" } }
    );
  }

  // ── Проксируем к Microsoft ──
  const t0 = performance.now();
  console.log("[proxy] →", url);

  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch(url, {
        method:  "GET",
        headers,
        signal:  controller.signal,
      });
    } finally {
      clearTimeout(tid);
    }

    const text     = await response.text();
    const duration = (performance.now() - t0).toFixed(0);

    console.log(
      "[proxy] ← " + response.status + " | " + text.length + "b | " + duration + "ms | body: " + text.slice(0, 150)
    );

    // Возвращаем текст ответа как есть — воркер сам разберётся с ошибками MS
    // Всегда 200 чтобы воркер мог прочитать тело (даже если MS вернул 403/429)
    return new Response(text, {
      status: 200,
      headers: {
        "Content-Type":    "application/json; charset=utf-8",
        "X-Ms-Status":     String(response.status),
        "X-Proxy-Ms-Duration": duration,
      },
    });

  } catch (err) {
    const duration    = (performance.now() - t0).toFixed(0);
    const msg         = err instanceof Error ? err.message : String(err);
    const isTimeout   = msg.includes("abort") || msg.includes("timed out");

    console.error(`[proxy] ${isTimeout ? "timeout" : "error"} after ${duration}ms:`, msg);

    return new Response(
      JSON.stringify({
        error:    isTimeout ? "Gateway Timeout" : "Gateway Error",
        details:  msg,
        duration: `${duration}ms`,
      }),
      {
        status:  isTimeout ? 504 : 502,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}

Deno.serve(handler);
