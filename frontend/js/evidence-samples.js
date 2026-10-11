/* Built-in sample evidence, forensic helpers and Tamper Lab alterations. Everything is generated
 * in the browser and is fictional: IP addresses come from the RFC 5737 documentation ranges
 * (198.51.100.0/24, 203.0.113.0/24), the domain ends in .example, the chat handles are invented
 * and the CCTV still is drawn on a <canvas>. The same case number always produces the same files.
 */
(function () {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const pad = (n, w = 2) => String(n).padStart(w, "0");

  /** Small deterministic PRNG (FNV-1a seed + xorshift32). */
  function rng(seed) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < seed.length; i++) {
      h ^= seed.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return () => {
      h ^= h << 13;
      h >>>= 0;
      h ^= h >>> 17;
      h ^= h << 5;
      h >>>= 0;
      return h / 4294967296;
    };
  }
  const int = (r, lo, hi) => lo + Math.floor(r() * (hi - lo + 1));

  // ---------- dates (the incident happened two nights before the case was opened) ----------
  function incidentDay(ctx) {
    const d = new Date((Number(ctx.caseCreatedAt) - 2 * 86400) * 1000);
    d.setHours(0, 0, 0, 0);
    return d;
  }
  const at = (day, h, m, s) => {
    const d = new Date(day);
    d.setHours(h, m, s, 0);
    return d;
  };
  const plus = (d, sec) => new Date(d.getTime() + sec * 1000);
  function tz(d) {
    const o = -d.getTimezoneOffset();
    return (o >= 0 ? "+" : "-") + pad(Math.floor(Math.abs(o) / 60)) + pad(Math.abs(o) % 60);
  }
  const clf = (d) => `${pad(d.getDate())}/${MON[d.getMonth()]}/${d.getFullYear()}:${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${tz(d)}`;
  const isoTime = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const chatTime = (d) => `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const stamp = (d) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;

  /** The intruder's address, shared by the server log and the chat (so the evidence corroborates). */
  const attackerIp = (ctx) => `203.0.113.${int(rng("ip|" + ctx.caseNumber), 21, 249)}`;
  /** Size of the stolen customer export (the log records it, the chat boasts about it). */
  const exportBytes = (ctx) => int(rng("export|" + ctx.caseNumber), 4600000, 5100000);

  const SERVER = "billing.riverton-city.example";
  const DESC = {
    log: `Access log of the municipal billing web server (${SERVER}) for the night of the incident, copied from the server.`,
    cctv: "CCTV still from camera 03 (corridor outside server room B), exported from the building's video recorder.",
    chat: 'Chat export from a phone seized from a suspect (group "night shift").',
  };

  // ---------- 1. web-server access log ----------
  function makeLog(ctx) {
    const r = rng("log|" + ctx.caseNumber);
    const day = incidentDay(ctx);
    const ip = attackerIp(ctx);
    const users = Array.from({ length: 6 }, () => `198.51.100.${int(r, 10, 240)}`);
    const browsers = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    ];
    const bot = "python-requests/2.31.0";
    const normal = [
      ["GET", "/", 200, 5123],
      ["GET", "/bill/view?acct=", 200, 0],
      ["GET", "/static/app.css", 200, 18233],
      ["POST", "/bill/pay", 302, 0],
      ["GET", "/receipt?no=", 200, 0],
      ["GET", "/help/tariffs", 200, 9412],
    ];
    const lines = [];
    const add = (d, who, user, method, path, status, bytes, agent) =>
      lines.push(`${who} - ${user} [${clf(d)}] "${method} ${path} HTTP/1.1" ${status} ${bytes} "-" "${agent}"`);
    const browse = (from, n) => {
      let t = from;
      for (let i = 0; i < n; i++) {
        t = plus(t, int(r, 25, 110));
        const [m, p, s, b] = normal[int(r, 0, normal.length - 1)];
        const path = p.endsWith("=") ? p + int(r, 100200, 998800) : p;
        add(t, users[int(r, 0, users.length - 1)], "-", m, path, s, b || int(r, 2100, 7600), browsers[int(r, 0, 2)]);
      }
      return t;
    };
    browse(at(day, 1, 48, 5), 9);
    let t = at(day, 2, 11, int(r, 1, 9));
    const fails = int(r, 31, 43);
    for (let i = 0; i < fails; i++) {
      add(t, ip, "-", "POST", "/admin/login", 401, 312, bot);
      t = plus(t, int(r, 3, 6));
    }
    add(t, ip, "-", "POST", "/admin/login", 302, 0, bot);
    t = plus(t, 2);
    add(t, ip, "admin", "GET", "/admin/dashboard", 200, 8812, bot);
    t = plus(t, int(r, 60, 95));
    add(t, ip, "admin", "GET", "/admin/reports/export?table=customers&format=csv", 200, exportBytes(ctx), bot);
    t = plus(t, int(r, 20, 40));
    add(t, ip, "admin", "GET", "/admin/logout", 302, 0, bot);
    browse(plus(t, 300), 6);
    return {
      bytes: enc.encode(lines.join("\n") + "\n"),
      type: "text/plain",
      name: `${SERVER.split(".")[0]}-web01_access_${stamp(day)}.log`,
      description: DESC.log,
      sample: "log",
    };
  }

  // ---------- 2. CCTV still (PNG drawn on a canvas) ----------
  const personX = (ctx) => int(rng("cctv-x|" + ctx.caseNumber), 236, 268);
  function cctvTime(ctx) {
    const r = rng("cctv-t|" + ctx.caseNumber);
    return at(incidentDay(ctx), 2, int(r, 6, 9), int(r, 0, 59));
  }

  function canvasBytes(canvas, type = "image/png", quality) {
    return new Promise((resolve, reject) =>
      canvas.toBlob(async (b) => (b ? resolve(new Uint8Array(await b.arrayBuffer())) : reject(new Error("Could not encode the image"))), type, quality)
    );
  }

  function drawTimestamp(g, H, text) {
    g.fillStyle = "#000";
    g.fillRect(8, H - 30, 176, 22);
    g.fillStyle = "#f4f4f4";
    g.font = "bold 13px Consolas, 'Courier New', monospace";
    g.textBaseline = "middle";
    g.fillText(text, 14, H - 19);
  }

  function paintCctv(ctx) {
    const W = 480;
    const H = 270;
    const r = rng("cctv|" + ctx.caseNumber);
    const c = document.createElement("canvas");
    c.width = W;
    c.height = H;
    const g = c.getContext("2d");
    // wall and floor
    let gr = g.createLinearGradient(0, 0, 0, 190);
    gr.addColorStop(0, "#34404a");
    gr.addColorStop(1, "#222b32");
    g.fillStyle = gr;
    g.fillRect(0, 0, W, H);
    gr = g.createLinearGradient(0, 180, 0, H);
    gr.addColorStop(0, "#47515a");
    gr.addColorStop(1, "#2a3036");
    g.fillStyle = gr;
    g.beginPath();
    g.moveTo(0, 196);
    g.lineTo(W, 182);
    g.lineTo(W, H);
    g.lineTo(0, H);
    g.fill();
    g.strokeStyle = "rgba(255,255,255,0.06)";
    for (let i = -6; i <= 14; i++) {
      g.beginPath();
      g.moveTo(240 + i * 22, 190);
      g.lineTo(240 + i * 70, H);
      g.stroke();
    }
    // ceiling light
    gr = g.createRadialGradient(330, -10, 5, 330, -10, 230);
    gr.addColorStop(0, "rgba(255,255,230,0.35)");
    gr.addColorStop(1, "rgba(255,255,230,0)");
    g.fillStyle = gr;
    g.fillRect(0, 0, W, H);
    // server racks with status LEDs
    for (const x of [18, 102]) {
      g.fillStyle = "#12171b";
      g.fillRect(x, 58, 72, 150);
      g.strokeStyle = "#45515c";
      g.lineWidth = 2;
      g.strokeRect(x, 58, 72, 150);
      g.lineWidth = 1;
      for (let y = 66; y < 200; y += 11) {
        g.fillStyle = "#1d252b";
        g.fillRect(x + 6, y, 60, 8);
        g.fillStyle = r() < 0.75 ? "#4ade80" : "#fbbf24";
        g.fillRect(x + 56, y + 3, 3, 3);
      }
    }
    // door to server room B (slightly open) and card reader
    g.fillStyle = "#5a646d";
    g.fillRect(300, 66, 88, 130);
    g.fillStyle = "#0a0d10";
    g.fillRect(306, 72, 76, 124);
    g.fillStyle = "#6b7680";
    g.beginPath();
    g.moveTo(318, 72);
    g.lineTo(382, 72);
    g.lineTo(382, 196);
    g.lineTo(318, 200);
    g.fill();
    g.fillStyle = "#c9d1d8";
    g.fillRect(326, 128, 4, 14);
    g.fillStyle = "#dfe6ec";
    g.fillRect(312, 48, 76, 13);
    g.fillStyle = "#1f2930";
    g.font = "bold 9px Arial, sans-serif";
    g.textBaseline = "middle";
    g.textAlign = "center";
    g.fillText("SERVER RM B", 350, 55);
    g.textAlign = "start";
    g.fillStyle = "#2b3238";
    g.fillRect(398, 118, 12, 18);
    g.fillStyle = "#ef4444";
    g.fillRect(402, 122, 4, 4);
    // the person at the door, holding a laptop
    const px = personX(ctx);
    g.fillStyle = "#07090b";
    g.beginPath();
    g.arc(px, 106, 11, 0, Math.PI * 2);
    g.fill();
    g.beginPath();
    g.moveTo(px - 19, 124);
    g.quadraticCurveTo(px, 114, px + 19, 124);
    g.lineTo(px + 15, 182);
    g.lineTo(px - 15, 182);
    g.closePath();
    g.fill();
    g.fillRect(px - 13, 180, 11, 30);
    g.fillRect(px + 2, 180, 11, 30);
    g.strokeStyle = "rgba(220,235,255,0.18)";
    g.stroke();
    g.fillStyle = "#1b2228";
    g.fillRect(px - 14, 142, 28, 18);
    g.fillStyle = "rgba(120,170,255,0.55)";
    g.fillRect(px - 11, 144, 22, 3);
    // CCTV look: tint, vignette, scan lines
    g.fillStyle = "rgba(60,110,80,0.13)";
    g.fillRect(0, 0, W, H);
    gr = g.createRadialGradient(W / 2, H / 2, 90, W / 2, H / 2, 300);
    gr.addColorStop(0, "rgba(0,0,0,0)");
    gr.addColorStop(1, "rgba(0,0,0,0.55)");
    g.fillStyle = gr;
    g.fillRect(0, 0, W, H);
    g.fillStyle = "rgba(0,0,0,0.13)";
    for (let y = 0; y < H; y += 3) g.fillRect(0, y, W, 1);
    // on-screen display
    g.font = "bold 13px Consolas, 'Courier New', monospace";
    g.textBaseline = "middle";
    g.fillStyle = "#f4f4f4";
    g.fillText("CAM 03  CORRIDOR / SERVER RM B", 10, 16);
    g.fillStyle = "#ef4444";
    g.beginPath();
    g.arc(W - 58, 16, 5, 0, Math.PI * 2);
    g.fill();
    g.fillStyle = "#f4f4f4";
    g.fillText("REC", W - 48, 16);
    drawTimestamp(g, H, isoTime(cctvTime(ctx)));
    return c;
  }

  async function makeCctv(ctx) {
    const t = cctvTime(ctx);
    return {
      bytes: await canvasBytes(paintCctv(ctx)),
      type: "image/png",
      name: `cam03_server-room-b_${stamp(t)}-${pad(t.getHours())}${pad(t.getMinutes())}.png`,
      description: DESC.cctv,
      sample: "cctv",
      meta: { timestamp: isoTime(t) },
    };
  }

  // ---------- 3. chat export ----------
  function makeChat(ctx) {
    const day = incidentDay(ctx);
    const r = rng("chat|" + ctx.caseNumber);
    const ip = attackerIp(ctx);
    const prev = new Date(day.getTime() - 86400000);
    let t = at(prev, 23, int(r, 40, 52), int(r, 0, 59));
    const msgs = [
      ["nightowl", "you still have the url of the old billing admin panel?"],
      ["r00tcause", `${SERVER}/admin - no lockout on the login page`],
      ["nightowl", "ok. tonight around 2"],
      ["r00tcause", "use the vps, not your home line"],
      ["nightowl", `vps is ${ip}, it's clean`],
    ];
    const lines = [`Chat export - group "night shift" - 2 participants`, `Exported from a seized phone (demo data, fictional)`, ""];
    for (const [who, text] of msgs) {
      lines.push(`[${chatTime(t)}] ${who}: ${text}`);
      t = plus(t, int(r, 40, 200));
    }
    t = at(day, 2, 10, int(r, 30, 59));
    const late = [
      ["nightowl", "starting"],
      ["nightowl", "in. admin panel is open"],
      ["nightowl", `customer export done, ${(exportBytes(ctx) / 1048576).toFixed(1)} MB`],
      ["r00tcause", "wipe the server logs"],
      ["nightowl", "can't, they are copied to the central log server. doesn't matter"],
      ["r00tcause", "delete this chat"],
    ];
    const gaps = [200, 140, 70, 40, 50];
    late.forEach(([who, text], i) => {
      lines.push(`[${chatTime(t)}] ${who}: ${text}`);
      t = plus(t, (gaps[i] || 30) + int(r, 0, 25));
    });
    return {
      bytes: enc.encode(lines.join("\n") + "\n"),
      type: "text/plain",
      name: "chat_export_night-shift.txt",
      description: DESC.chat,
      sample: "chat",
    };
  }

  const SAMPLES = [
    { id: "log", label: "Sample: web-server access log (intrusion)", description: DESC.log, hint: "Synthetic access log: dozens of failed admin logins from one address, then a successful login and a customer-data export." },
    { id: "cctv", label: "Sample: CCTV still at the server-room door (PNG)", description: DESC.cctv, hint: "Synthetic CCTV frame drawn on a canvas, with a timestamp overlay." },
    { id: "chat", label: "Sample: chat export from a seized phone", description: DESC.chat, hint: "Synthetic chat between two suspects that mentions the same IP address as the log." },
  ];

  async function make(kind, ctx) {
    if (kind === "log") return makeLog(ctx);
    if (kind === "cctv") return makeCctv(ctx);
    if (kind === "chat") return makeChat(ctx);
    throw new Error("Unknown sample " + kind);
  }

  // ---------- file kinds ----------
  function kindOf(file) {
    const type = (file && file.type) || "";
    if (/^image\/(png|jpeg|webp|gif|bmp)$/.test(type)) return "image";
    if (/^text\//.test(type) || /\.(txt|log|csv|json|xml|md|eml|html?)$/i.test((file && file.name) || "")) return "text";
    return "other";
  }

  async function decodeImage(bytes, type) {
    return createImageBitmap(new Blob([bytes], { type }));
  }

  async function thumbnail(bytes, type, max = 200) {
    const bmp = await decodeImage(bytes, type);
    const s = Math.min(1, max / Math.max(bmp.width, bmp.height));
    const c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(bmp.width * s));
    c.height = Math.max(1, Math.round(bmp.height * s));
    c.getContext("2d").drawImage(bmp, 0, 0, c.width, c.height);
    return c.toDataURL("image/jpeg", 0.8);
  }

  // ---------- forensic analysis (used for the lab's report) ----------
  const CLF = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)/;
  const fmtMB = (n) => (n / 1048576).toFixed(1) + " MB";
  const clock = (s) => (s.split(":").slice(1, 4).join(":") || s).split(" ")[0];

  function analyseLog(text) {
    const rows = text.split("\n").map((l) => CLF.exec(l)).filter(Boolean);
    const ips = new Map();
    for (const m of rows) ips.set(m[1], (ips.get(m[1]) || 0) + 1);
    const fails = new Map();
    for (const m of rows) if (/login/i.test(m[5]) && m[6] === "401") fails.set(m[1], (fails.get(m[1]) || 0) + 1);
    const top = [...fails.entries()].sort((a, b) => b[1] - a[1])[0];
    if (!rows.length) return null;
    const findings = [`${rows.length} requests from ${ips.size} addresses parsed (Common Log Format).`];
    let summary = `${rows.length} requests parsed; no brute-force pattern found`;
    if (top) {
      const [ip, n] = top;
      const mine = rows.filter((m) => m[1] === ip);
      const firstFail = mine.find((m) => m[6] === "401");
      const success = mine.find((m) => /login/i.test(m[5]) && /^(200|302)$/.test(m[6]));
      const exports = mine.filter((m) => /export/i.test(m[5]));
      const exported = exports.reduce((s, m) => s + (Number(m[7]) || 0), 0);
      findings.push(`${n} failed logins (HTTP 401) on ${firstFail[5]} from ${ip}, starting ${clock(firstFail[3])}, automated client "${(mine[0].input.match(/"([^"]*)"$/) || [])[1] || "?"}".`);
      if (success) findings.push(`Successful login from the same address at ${clock(success[3])}, followed by ${mine.length - n - 1} authenticated requests as "admin".`);
      if (exports.length) findings.push(`${exports.length} data export(s) totalling ${fmtMB(exported)}: ${exports[0][5]}.`);
      summary = `${n} failed logins from ${ip}${success ? `, admin login at ${clock(success[3])}` : ""}${exports.length ? `, ${fmtMB(exported)} customer export` : ""}`;
    }
    return { method: "Parsed every line as Common Log Format; grouped requests by client address and status code.", findings, summary };
  }

  function analyseChat(text) {
    const msgs = text.split("\n").map((l) => /^\[([^\]]+)\] ([^:]+): (.*)$/.exec(l)).filter(Boolean);
    if (!msgs.length) return null;
    const people = [...new Set(msgs.map((m) => m[2]))];
    const ips = [...new Set(msgs.flatMap((m) => m[3].match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []))];
    const keys = msgs.filter((m) => /export|logs?|delete|admin|login/i.test(m[3]));
    const findings = [
      `${msgs.length} messages between ${people.join(" and ")}, from ${msgs[0][1]} to ${msgs[msgs.length - 1][1]}.`,
      ips.length ? `IP address(es) mentioned: ${ips.join(", ")}.` : "No IP addresses mentioned.",
      `${keys.length} messages refer to the admin panel, the export or deleting logs.`,
    ];
    return {
      method: "Parsed the export line by line; extracted participants, times, IP addresses and keywords.",
      findings,
      summary: `${msgs.length} messages; ${ips.length ? `mentions ${ips.join(", ")}` : "no IPs"}; discusses the export and deleting logs`,
    };
  }

  async function analyseImage(bytes, type, meta) {
    const bmp = await decodeImage(bytes, type);
    const c = document.createElement("canvas");
    c.width = bmp.width;
    c.height = bmp.height;
    const g = c.getContext("2d", { willReadFrequently: true });
    g.drawImage(bmp, 0, 0);
    const px = g.getImageData(0, 0, c.width, c.height).data;
    let sum = 0;
    for (let i = 0; i < px.length; i += 4) sum += 0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2];
    const mean = Math.round(sum / (px.length / 4));
    const findings = [
      `Single frame, ${bmp.width} x ${bmp.height} pixels, ${type}; mean brightness ${mean}/255 (night-time scene).`,
      meta && meta.timestamp ? `On-screen timestamp reads ${meta.timestamp}; one person stands at the door of server room B holding a laptop.` : "Visual examination of the frame (no metadata to compare).",
    ];
    return {
      method: "Decoded the image in the examiner's browser; measured the pixels and examined the frame.",
      findings,
      summary: meta && meta.timestamp ? `${bmp.width}x${bmp.height} frame; person at server room B door at ${meta.timestamp.slice(11)}` : `${bmp.width}x${bmp.height} image examined`,
    };
  }

  async function analyse(file) {
    const kind = kindOf(file);
    let out = null;
    if (kind === "text") {
      const text = dec.decode(file.bytes);
      out = analyseLog(text) || analyseChat(text);
      if (!out) {
        const lines = text.split("\n").length;
        out = { method: "Read the text file.", findings: [`${lines} lines of text examined.`], summary: `${lines} lines of text examined` };
      }
    } else if (kind === "image") out = await analyseImage(file.bytes, file.type, file.meta);
    else out = { method: "Binary file.", findings: [`${file.bytes.length} bytes examined.`], summary: `${file.bytes.length} bytes examined` };
    return out;
  }

  // ---------- derived evidence (what a forensic lab extracts from an item) ----------
  async function derive(file, ctx) {
    const kind = kindOf(file);
    if (kind === "text") {
      const text = dec.decode(file.bytes);
      const log = analyseLog(text);
      if (log) {
        const rows = text.split("\n").map((l) => [l, CLF.exec(l)]).filter(([, m]) => m);
        const counts = new Map();
        for (const [, m] of rows) if (m[6] === "401") counts.set(m[1], (counts.get(m[1]) || 0) + 1);
        const ip = ([...counts.entries()].sort((a, b) => b[1] - a[1])[0] || [rows[0][1][1]])[0];
        const keep = rows.filter(([, m]) => m[1] === ip).map(([l]) => l);
        return {
          bytes: enc.encode(keep.join("\n") + "\n"),
          type: "text/plain",
          name: `access_extract_${ip}.log`,
          description: `Extract: the ${keep.length} requests from ${ip} (filtered from the full log)`,
          sample: null,
        };
      }
      const chat = text.split("\n").filter((l) => /^\[[^\]]*, 0[2-3]:/.test(l));
      if (chat.length) {
        return {
          bytes: enc.encode(chat.join("\n") + "\n"),
          type: "text/plain",
          name: "chat_extract_0200-0400.txt",
          description: `Extract: the ${chat.length} messages sent between 02:00 and 04:00 on the night of the incident`,
          sample: null,
        };
      }
      return null;
    }
    if (kind === "image") {
      const bmp = await decodeImage(file.bytes, file.type);
      const px = file.sample === "cctv" && ctx ? personX(ctx) : Math.round(bmp.width / 2);
      const sx = Math.max(0, Math.min(bmp.width - 150, px - 62));
      const sy = Math.max(0, Math.min(bmp.height - 135, Math.round(bmp.height * 0.3)));
      const c = document.createElement("canvas");
      c.width = 300;
      c.height = 270;
      const g = c.getContext("2d");
      g.filter = "brightness(1.7) contrast(1.35)";
      g.imageSmoothingQuality = "high";
      g.drawImage(bmp, sx, sy, 150, 135, 0, 0, 300, 270);
      g.filter = "none";
      g.fillStyle = "rgba(0,0,0,0.6)";
      g.fillRect(0, 0, 300, 20);
      g.fillStyle = "#fff";
      g.font = "bold 11px Consolas, 'Courier New', monospace";
      g.textBaseline = "middle";
      g.fillText("ENHANCED CROP 2x - FORENSIC LAB", 8, 10);
      return {
        bytes: await canvasBytes(c),
        type: "image/png",
        name: file.name.replace(/\.[^.]+$/, "") + "_enhanced-crop.png",
        description: "Enhanced 2x crop of the person at the server-room door (brightness and contrast raised)",
        sample: null,
      };
    }
    return null;
  }

  // ---------- Tamper Lab ----------
  const ALTERATIONS = [
    { id: "line", kinds: ["text"], label: "Change one character", hint: "Changes one digit in one line: the intruder's IP address in the successful-login line now points at someone else." },
    { id: "delete", kinds: ["text"], label: "Delete one line", hint: "Removes the single most incriminating line (the data export)." },
    { id: "pixel", kinds: ["image"], label: "Edit one pixel", hint: "Adds 1 to the red value of the centre pixel. Nobody could see this change." },
    { id: "timestamp", kinds: ["image"], label: "Change the timestamp", hint: "Paints a different time over the CCTV timestamp: a classic alibi forgery." },
    { id: "bit", kinds: ["other"], label: "Flip one bit", hint: "Flips the lowest bit of the middle byte of the file." },
    { id: "append", kinds: ["text", "image", "other"], label: "Append one byte", hint: "Adds one invisible byte at the end of the file (a newline or a zero byte). Nothing visible changes." },
  ];
  const alterationsFor = (file) => ALTERATIONS.filter((a) => a.kinds.includes(kindOf(file)));

  const suffix = (name, tag) => (/\.[^.]+$/.test(name) ? name.replace(/(\.[^.]+)$/, `-${tag}$1`) : `${name}-${tag}`);

  function zoom(imageData, W, x, y, n = 11, scale = 12) {
    const c = document.createElement("canvas");
    c.width = n * scale;
    c.height = n * scale;
    const g = c.getContext("2d");
    const h = (n - 1) / 2;
    for (let j = 0; j < n; j++) {
      for (let i = 0; i < n; i++) {
        const xx = Math.min(W - 1, Math.max(0, x - h + i));
        const yy = Math.max(0, y - h + j);
        const k = (yy * W + xx) * 4;
        g.fillStyle = `rgb(${imageData[k]},${imageData[k + 1]},${imageData[k + 2]})`;
        g.fillRect(i * scale, j * scale, scale, scale);
      }
    }
    g.strokeStyle = "#ef4444";
    g.lineWidth = 2;
    g.strokeRect(h * scale + 1, h * scale + 1, scale - 2, scale - 2);
    return c.toDataURL("image/png");
  }

  async function alter(id, file) {
    const kind = kindOf(file);
    if (id === "append") {
      const out = new Uint8Array(file.bytes.length + 1);
      out.set(file.bytes);
      out[file.bytes.length] = kind === "text" ? 0x0a : 0x00;
      return { bytes: out, type: file.type, name: suffix(file.name, "appended"), detail: { kind: "append", byte: kind === "text" ? "0x0a (a newline)" : "0x00" } };
    }
    if (id === "bit") {
      const out = file.bytes.slice();
      const off = Math.floor(out.length / 2);
      const before = out[off];
      out[off] ^= 1;
      return { bytes: out, type: file.type, name: suffix(file.name, "bitflip"), detail: { kind: "bit", offset: off, before, after: out[off] } };
    }
    if (id === "line" || id === "delete") {
      const lines = dec.decode(file.bytes).split("\n");
      const nonEmpty = (l) => l.trim().length > 0;
      const mid = Math.floor(lines.length / 2);
      if (id === "line") {
        let idx = lines.findIndex((l) => /login/i.test(l) && /" (200|302) /.test(l));
        if (idx < 0) idx = lines.findIndex((l) => /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(l));
        if (idx < 0) idx = lines.findIndex((l, i) => i >= mid && /\d/.test(l));
        if (idx < 0) idx = lines.findIndex((l) => /\d/.test(l));
        if (idx < 0) idx = Math.max(0, lines.findIndex(nonEmpty));
        const line = lines[idx];
        const ip = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.exec(line);
        let col = ip ? ip.index + ip[0].length - 1 : line.search(/\d/);
        if (col < 0) col = Math.max(0, line.search(/[A-Za-z]/));
        const ch = line[col] || " ";
        const nc = /\d/.test(ch) ? String((Number(ch) + 1) % 10) : ch === ch.toUpperCase() ? ch.toLowerCase() : ch.toUpperCase();
        const after = line.slice(0, col) + (nc === ch ? "#" : nc) + line.slice(col + 1);
        lines[idx] = after;
        return {
          bytes: enc.encode(lines.join("\n")),
          type: file.type,
          name: suffix(file.name, "edited"),
          detail: { kind: "line", lineNo: idx + 1, before: line, after, col },
        };
      }
      // (skip line 1: a chat export's header line also contains the word "export")
      let idx = lines.findIndex((l, i) => i > 0 && /export/i.test(l));
      if (idx < 0) idx = lines.findIndex((l) => /delete|password|admin/i.test(l));
      if (idx < 0) idx = lines.findIndex((l, i) => i >= mid && nonEmpty(l));
      if (idx < 0) idx = 0;
      const removed = lines.splice(idx, 1)[0];
      return { bytes: enc.encode(lines.join("\n")), type: file.type, name: suffix(file.name, "line-deleted"), detail: { kind: "delete", lineNo: idx + 1, removed } };
    }
    // image edits: decode, change pixels, encode as PNG again
    const bmp = await decodeImage(file.bytes, file.type);
    const W = bmp.width;
    const H = bmp.height;
    const c = document.createElement("canvas");
    c.width = W;
    c.height = H;
    const g = c.getContext("2d", { willReadFrequently: true });
    g.drawImage(bmp, 0, 0);
    if (id === "pixel") {
      const img = g.getImageData(0, 0, W, H);
      const x = Math.floor(W / 2);
      const y = Math.floor(H / 2);
      const k = (y * W + x) * 4;
      const before = [img.data[k], img.data[k + 1], img.data[k + 2]];
      const zoomBefore = zoom(img.data, W, x, y);
      img.data[k] = img.data[k] < 255 ? img.data[k] + 1 : 254;
      img.data[k + 3] = 255;
      const after = [img.data[k], img.data[k + 1], img.data[k + 2]];
      g.putImageData(img, 0, 0);
      return {
        bytes: await canvasBytes(c),
        type: "image/png",
        name: suffix(file.name.replace(/\.[^.]+$/, ".png"), "pixel-edited"),
        detail: { kind: "pixel", x, y, before, after, zoomBefore, zoomAfter: zoom(img.data, W, x, y) },
      };
    }
    if (id === "timestamp") {
      const before = (file.meta && file.meta.timestamp) || null;
      let after = "2026-01-01 03:41:07";
      if (before) {
        const h = (Number(before.slice(11, 13)) + 1) % 24;
        after = before.slice(0, 11) + pad(h) + ":" + pad((Number(before.slice(14, 16)) + 32) % 60) + before.slice(16);
      }
      drawTimestamp(g, H, after);
      return {
        bytes: await canvasBytes(c),
        type: "image/png",
        name: suffix(file.name.replace(/\.[^.]+$/, ".png"), "retimed"),
        detail: { kind: "timestamp", before, after },
      };
    }
    throw new Error("Unknown alteration " + id);
  }

  window.EvidenceSamples = { SAMPLES, make, kindOf, thumbnail, analyse, derive, ALTERATIONS, alterationsFor, alter, attackerIp, incidentDay };
})();
