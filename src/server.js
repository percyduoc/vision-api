import "dotenv/config";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import fetch from "node-fetch";
import { Pool } from "pg";
import { z } from "zod";

const app = express();
app.use(helmet());
app.use(cors()); // en prod: limita origins
app.use(express.json({ limit: "256kb" }));
app.use(morgan("tiny"));

// ====== ENV ======
const {
  DATABASE_URL,
  PGSSL = "true",
  PORT = 8080,
  API_KEY = "supersecreto",       // Bearer para ingestión
  ADMIN_KEY = "",                 // opcional p/ reset
  CAMERA_SNAPSHOT_URL = "",       // ej: http://IP:8080/shot.jpg
  SNAP_BASIC_USER = "",           // opcional: basic auth simple del snapshot
  SNAP_BASIC_PASS = "",           // opcional
  METRICS_WINDOW_MIN = "10",      // minutos de ventana para el gráfico
  DEFAULT_SOURCE_ID = "",         // opcional: cámara por defecto en el dashboard
} = process.env;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

// ====== Zod Schemas ======
const Payload = z.object({
  source_id: z.string().min(1),
  timestamp: z.string().datetime(), // ISO8601
  count: z.number().int().nonnegative(),
  unique: z.number().int().nonnegative().optional().default(0),
  max: z.number().int().nonnegative().nullable().optional(),
  min: z.number().int().nonnegative().nullable().optional(),
  avg_window: z.number().nullable().optional(),
  fps: z.number().nullable().optional(),
});

// ====== Helpers ======
function toEpochSec(isoTs) {
  return Math.floor(new Date(isoTs).getTime() / 1000);
}
function secondsToHMS(s) {
  s = Math.max(0, Math.floor(s));
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${h}:${m}:${ss}`;
}

async function getCamId(client, sourceCode) {
  const cam = await client.query(
    "SELECT id FROM camaras WHERE codigo = $1 LIMIT 1",
    [sourceCode]
  );
  if (cam.rowCount === 0) return null;
  return cam.rows[0].id;
}

// ====== Rutas ======
app.get("/health", (_req, res) => res.json({ ok: true }));

/**
 * Ingesta de métricas desde el worker
 * Header requerido: Authorization: Bearer ${API_KEY}
 */
app.post("/api/metrics", async (req, res) => {
  try {
    if ((req.headers.authorization || "") !== `Bearer ${API_KEY}`) {
      return res.status(401).json({ error: "unauthorized" });
    }
    const b = Payload.parse(req.body);
    const ts_sec = toEpochSec(b.timestamp);

    const client = await pool.connect();
    try {
      const camara_id = await getCamId(client, b.source_id);
      if (!camara_id) {
        return res
          .status(404)
          .json({ error: "camera_not_found", source_id: b.source_id });
      }

      // Asegúrate de tener UNIQUE(camara_id, ts_sec) en metricas
      // y columnas: ts timestamptz, ts_sec int, count int, unique_count int,
      // max_count int, min_count int, roll_avg float8, fps float8
      const q = `
        INSERT INTO metricas
          (camara_id, ts, ts_sec, count, unique_count, max_count, min_count, roll_avg, fps)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (camara_id, ts_sec)
        DO UPDATE SET
          count        = EXCLUDED.count,
          unique_count = EXCLUDED.unique_count,
          max_count    = GREATEST(COALESCE(metricas.max_count, 0), COALESCE(EXCLUDED.max_count, 0)),
          min_count    = LEAST(
                           COALESCE(metricas.min_count, EXCLUDED.min_count),
                           EXCLUDED.min_count
                         ),
          roll_avg     = EXCLUDED.roll_avg,
          fps          = EXCLUDED.fps
        RETURNING id
      `;
      const params = [
        camara_id,
        b.timestamp,
        ts_sec,
        b.count,
        b.unique ?? 0,
        b.max ?? null,
        b.min ?? null,
        b.avg_window ?? null,
        b.fps ?? null,
      ];

      const { rows } = await client.query(q, params);
      res.json({ ok: true, id: rows[0].id });
    } finally {
      client.release();
    }
  } catch (e) {
    if (e instanceof z.ZodError)
      return res.status(400).json({ error: "bad_payload", issues: e.issues });
    console.error(e);
    res.status(500).json({ error: "server_error" });
  }
});

/**
 * Dashboard HTML
 */
app.get("/", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8").send(DASH_HTML);
});

/**
 * API para el dashboard:
 * GET /metrics?source_id=cam_lobby_1&minutes=10
 * Lee últimos N minutos desde Postgres y arma KPIs + serie
 */
app.get("/metrics", async (req, res) => {
  const source_id = (req.query.source_id || DEFAULT_SOURCE_ID || "").toString();
  const minutes = Math.max(
    1,
    Math.min(60 * 6, Number(req.query.minutes || METRICS_WINDOW_MIN))
  ); // 1..360 min

  try {
    const client = await pool.connect();
    try {
      let camara_id = null;
      if (source_id) {
        camara_id = await getCamId(client, source_id);
        if (!camara_id) {
          return res.json({ now: {}, history: [] });
        }
      } else {
        // si no hay source_id, tomar la primera cámara
        const r = await client.query("SELECT id, codigo FROM camaras LIMIT 1");
        if (r.rowCount) {
          camara_id = r.rows[0].id;
        } else {
          return res.json({ now: {}, history: [] });
        }
      }

      // Traer últimos N minutos
      const q = `
        SELECT ts, count, unique_count, max_count, min_count, roll_avg, fps
        FROM metricas
        WHERE camara_id = $1
          AND ts >= NOW() - ($2::text || ' minutes')::interval
        ORDER BY ts ASC
      `;
      const { rows } = await client.query(q, [camara_id, String(minutes)]);

      if (!rows.length) return res.json({ now: {}, history: [] });

      // Serie
      const history = rows.map((r) => ({
        t: r.ts.toISOString().replace(/\.\d+Z$/, "Z"),
        count: Number(r.count || 0),
      }));

      // KPIs
      const counts = rows.map((r) => Number(r.count || 0));
      const cNow = counts[counts.length - 1];
      const cMax = Math.max(...counts);
      const cMin = Math.min(...counts);
      const prom =
        counts.reduce((a, b) => a + b, 0) / Math.max(1, counts.length);

      // trend 30s: últimos 5s vs previos 30s
      const nowEpoch = Date.now();
      const withTs = rows.map((r) => ({
        epoch: new Date(r.ts).getTime(),
        count: Number(r.count || 0),
      }));
      const recent = withTs.filter((p) => nowEpoch - p.epoch <= 5000);
      const prev30 = withTs.filter(
        (p) => nowEpoch - p.epoch > 5000 && nowEpoch - p.epoch <= 35000
      );
      const avgRecent =
        recent.length > 0
          ? recent.reduce((a, b) => a + b.count, 0) / recent.length
          : cNow;
      const avgPrev30 =
        prev30.length > 0
          ? prev30.reduce((a, b) => a + b.count, 0) / prev30.length
          : cNow;
      const trend30s = Number((avgRecent - avgPrev30).toFixed(2));

      // cuándo ocurrió el máximo
      const maxIdx = counts.indexOf(cMax);
      const max_time = history[maxIdx]?.t || "—";

      // “uptime” ficticio: desde el primer punto del rango
      const uptimeSec = Math.max(
        0,
        Math.floor((nowEpoch - withTs[0].epoch) / 1000)
      );

      // Conserva del último row si existen
      const last = rows[rows.length - 1];
      const now = {
        timestamp: history[history.length - 1].t,
        count: cNow,
        max: cMax,
        min: cMin,
        prom: Number(prom.toFixed(2)),
        trend30s,
        max_time,
        uptime: secondsToHMS(uptimeSec),
        unicos: Number(last.unique_count || 0),
        fps: Number(last.fps || 0),
        roll_avg: Number(last.roll_avg || 0),
      };

      res.json({ now, history });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server_error" });
  }
});

/**
 * Snapshot proxy (opcional)
 * Si tu cámara expone /shot.jpg sin auth o con Basic, puedes mostrar la “vista en vivo”.
 * Para Digest, usa tu proxy Python.
 */
app.get("/snapshot.jpg", async (_req, res) => {
  try {
    if (!CAMERA_SNAPSHOT_URL) return res.status(404).end();

    const headers = {};
    if (SNAP_BASIC_USER && SNAP_BASIC_PASS) {
      const token = Buffer.from(`${SNAP_BASIC_USER}:${SNAP_BASIC_PASS}`).toString("base64");
      headers["Authorization"] = `Basic ${token}`;
    }
    const r = await fetch(CAMERA_SNAPSHOT_URL, { headers });
    if (!r.ok) return res.status(502).end();
    const buf = Buffer.from(await r.arrayBuffer());
    res.set("Content-Type", "image/jpeg").send(buf);
  } catch {
    res.status(502).end();
  }
});

/**
 * Reset (opcional): borra últimos X minutos de una cámara
 * Header: X-Admin-Key: ${ADMIN_KEY}
 * Body: { source_id: "cam_lobby_1", minutes: 10 }
 */
app.post("/reset", async (req, res) => {
  try {
    if (!ADMIN_KEY || req.headers["x-admin-key"] !== ADMIN_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }
    const source_id = String(req.body?.source_id || "");
    const minutes = Math.max(1, Math.min(60 * 6, Number(req.body?.minutes || 10)));

    const client = await pool.connect();
    try {
      const camara_id = await getCamId(client, source_id);
      if (!camara_id) return res.json({ ok: true, deleted: 0 });

      const del = await client.query(
        `DELETE FROM metricas
         WHERE camara_id = $1
           AND ts >= NOW() - ($2::text || ' minutes')::interval`,
        [camara_id, String(minutes)]
      );
      res.json({ ok: true, deleted: del.rowCount });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server_error" });
  }
});

app.listen(PORT, () => {
  console.log(`API + Dashboard up on :${PORT}`);
});

// ====== HTML del dashboard ======
const DASH_HTML = `<!DOCTYPE html>
<html lang="es"><head>
<meta charset="utf-8"><title>Dashboard Personas</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#0b0f14; --card:#121821; --muted:#8aa0b2; --fg:#e9f0f6; --border:#1e2733; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,'Helvetica Neue',Arial,'Noto Sans'; background:#0b0f14; color:var(--fg); }
  header { padding:20px 22px; background:linear-gradient(90deg,#0b6b68,#1a8d75); box-shadow:0 2px 0 #0e3e3c; }
  header h1 { margin:0; font-size:20px; letter-spacing:.3px }
  .container { padding:18px 22px; }
  .grid { display:grid; grid-template-columns:repeat(6,minmax(160px,1fr)); gap:12px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:12px; }
  .kpi h2 { margin:0 0 6px; font-size:12px; color:var(--muted); font-weight:600 }
  .kpi .val { font-size:28px; font-weight:800 }
  .chip { display:inline-flex; gap:6px; padding:2px 8px; border-radius:9999px; font-size:12px; border:1px solid var(--border); color:var(--muted) }
  .chip.up { color:#97e0bb } .chip.down { color:#ffb3b3 }
  .row { display:grid; grid-template-columns:1.5fr .9fr; gap:12px; margin-top:12px }
  #chart { background:#0b0f14; border-radius:10px; border:1px solid var(--border); }
  .snapshot { width:100%; border-radius:10px; border:1px solid var(--border); background:#0b0f14; height:360px; object-fit:contain }
  .actions { display:flex; gap:10px; margin-top:8px }
  button { background:#173045; color:#d7e6f2; border:1px solid var(--border); padding:8px 12px; border-radius:10px; cursor:pointer; }
</style>
</head><body>
  <header><h1>Dashboard de personas (en vivo)</h1></header>
  <div class="container">
    <div class="grid">
      <div class="card kpi"><h2>Activos (ahora)</h2><div class="val" id="activos">0</div></div>
      <div class="card kpi"><h2>Pico (Max)</h2><div class="val"><span id="max">0</span></div><div class="meta" id="max_time">—</div></div>
      <div class="card kpi"><h2>Promedio</h2><div class="val" id="prom">0</div></div>
      <div class="card kpi"><h2>Únicos (sesión)</h2><div class="val" id="unicos">0</div></div>
      <div class="card kpi"><h2>FPS</h2><div class="val" id="fps">0</div></div>
      <div class="card kpi"><h2>Uptime</h2><div class="val" id="uptime">00:00:00</div></div>
    </div>

    <div class="row">
      <div class="card">
        <h3 class="panel-title">Serie temporal (últimos ~10 min) <span class="chip" id="ts">—</span> <span class="chip" id="trend"></span></h3>
        <canvas id="chart" width="800" height="360" style="display:block"></canvas>
        <div class="actions"><button id="resetBtn">Reset métricas</button></div>
      </div>
      <div class="card">
        <h3 class="panel-title">Vista en vivo</h3>
        <img id="snap" class="snapshot" alt="snapshot">
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
  <script>
    Chart.defaults.responsive = false; Chart.defaults.devicePixelRatio = 1;
    const Y_MAX = 10, WINDOW_POINTS = 600;
    const el = (id)=>document.getElementById(id);

    const ctx = document.getElementById('chart').getContext('2d');
    const chart = new Chart(ctx, {
      type: 'line',
      data: { labels: [], datasets: [{ label: 'Personas activas', data: [], fill: false, tension: 0.25 }] },
      options: {
        responsive:false, devicePixelRatio:1, animation:false, maintainAspectRatio:false,
        scales:{ x:{ title:{display:true,text:'Tiempo'}},
                 y:{ min:0, max:Y_MAX, beginAtZero:true, ticks:{ stepSize:1 }, title:{display:true,text:'Personas'} } },
        plugins:{ legend:{ display:false } }
      }
    });

    const DEFAULT_SOURCE_ID = "${(DEFAULT_SOURCE_ID || "").replace(/"/g,'\\"')}";
    async function tick(){
      try{
        const qs = new URLSearchParams({ source_id: DEFAULT_SOURCE_ID, minutes: "${METRICS_WINDOW_MIN}" });
        const res = await fetch('/metrics?' + qs.toString(), { cache:'no-store' });
        const data = await res.json();
        const now = data.now || {}; const history = data.history || [];

        el('activos').textContent = now.count ?? 0;
        el('max').textContent     = now.max ?? 0;
        el('max_time').textContent= now.max_time ?? '—';
        el('prom').textContent    = (now.prom ?? 0).toFixed(2);
        el('unicos').textContent  = now.unicos ?? 0;
        el('fps').textContent     = (now.fps ?? 0).toFixed(1);
        el('uptime').textContent  = now.uptime ?? '00:00:00';
        el('ts').textContent      = now.timestamp ?? '—';

        const trend = now.trend30s ?? 0;
        const tChip = document.getElementById('trend');
        if (trend > 0) { tChip.textContent = "↑ +" + trend.toFixed(2) + " vs 30s prev"; tChip.className = "chip up"; }
        else if (trend < 0) { tChip.textContent = "↓ " + trend.toFixed(2) + " vs 30s prev"; tChip.className = "chip down"; }
        else { tChip.textContent = "— trend 30s"; tChip.className = "chip"; }

        const view = history.slice(-WINDOW_POINTS);
        chart.data.labels.length = 0; chart.data.datasets[0].data.length = 0;
        for (let i = 0; i < view.length; i++) {
          chart.data.labels.push(view[i].t.slice(11,19)); // HH:MM:SS
          chart.data.datasets[0].data.push(view[i].count);
        }
        chart.update('none');

        const url = '/snapshot.jpg?t=' + Date.now();
        fetch(url, { cache:'no-store' }).then(r => { if (r.ok) document.getElementById('snap').src = url; }).catch(()=>{});
      } catch(e) { console.error(e); }
      finally { setTimeout(tick, 1000); }
    }
    tick();

    document.getElementById('resetBtn').onclick = async () => {
      const body = { source_id: DEFAULT_SOURCE_ID, minutes: ${Number(METRICS_WINDOW_MIN)} };
      try {
        await fetch('/reset', { method:'POST', headers: { 'Content-Type':'application/json', 'X-Admin-Key':'${ADMIN_KEY || ""}' }, body: JSON.stringify(body) });
      } catch(e) { console.error(e); }
    };
  </script>
</body></html>`;
