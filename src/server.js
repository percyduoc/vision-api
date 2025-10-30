import "dotenv/config";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import fetch from "node-fetch";
import { Pool } from "pg";
import { z } from "zod";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * ⚠️ IMPORTANTE (DB):
 * Asegúrate de tener ts_sec como INT generado desde ts y el índice único:
 * 
 * ALTER TABLE metricas DROP CONSTRAINT IF EXISTS metricas_pkey;
 * DROP INDEX IF EXISTS ux_metricas_camara_tssec;
 * ALTER TABLE metricas DROP COLUMN IF EXISTS ts_sec;
 * ALTER TABLE metricas
 *   ADD COLUMN ts_sec INT GENERATED ALWAYS AS (FLOOR(EXTRACT(EPOCH FROM ts))::INT) STORED;
 * CREATE UNIQUE INDEX IF NOT EXISTS ux_metricas_camara_tssec
 *   ON metricas (camara_id, ts_sec);
 */

const app = express();
app.use(helmet());

// ====== CORS (permitir Flutter web local y tu dominio de Render) ======
const allowedOrigins = [
  /^http:\/\/localhost:\d+$/,               // Flutter web dev
  'https://vision-api-wki3.onrender.com',   // tu API en Render
  // agrega aquí otros dominios front si tienes
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl/postman
    const ok = allowedOrigins.some((o) => o instanceof RegExp ? o.test(origin) : o === origin);
    return ok ? cb(null, true) : cb(new Error('CORS blocked'), false);
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: false,
  maxAge: 86400, // cachea preflight
}));

// Responder preflights explícitamente
app.options('*', cors());
 // en prod: limita origins
app.use(express.json({ limit: "256kb" }));
app.use(morgan("tiny"));

// ====== STATIC (self-hosted) ======
app.use(
  "/vendor",
  express.static(path.join(__dirname, "..", "node_modules", "chart.js", "dist"))
);
app.use("/static", express.static(path.join(__dirname, "..", "public")));

// ====== ENV ======
const {
  DATABASE_URL,
  PGSSL = "true",
  PORT = 8080,
  API_KEY = "supersecreto", // Bearer para ingestión
  ADMIN_KEY = "",           // opcional p/ reset
  CAMERA_SNAPSHOT_URL = "", // ej: http://IP:8080/shot.jpg
  SNAP_BASIC_USER = "",     // opcional: basic auth simple del snapshot
  SNAP_BASIC_PASS = "",     // opcional
  METRICS_WINDOW_MIN = "1000",// minutos de ventana para el gráfico
  DEFAULT_SOURCE_ID = "",   // opcional: cámara por defecto en el dashboard
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

async function getCapacidadLugarByCam(client, camaraId) {
  const { rows } = await client.query(
    `
    SELECT 
      l.capacidad_maxima,
      COALESCE(NULLIF(l.nombre, ''), c.codigo) AS lugar_nombre
    FROM camaras c
    LEFT JOIN lugares l ON l.id = c.lugar_id
    WHERE c.id = $1
    LIMIT 1
    `,
    [camaraId]
  );
  return{
    capacidad_maxima: rows?.[0]?.capacidad_maxima ?? null,
    lugar_nombre: rows?.[0]?.lugar_nombre ?? null,
  };


}
async function getLugarInfoByCam(client, camaraId) {
  const { rows } = await client.query(
    `
    SELECT 
      l.capacidad_maxima,
      COALESCE(NULLIF(l.nombre, ''), c.codigo) AS lugar_nombre
    FROM camaras c
    LEFT JOIN lugares l ON l.id = c.lugar_id
    WHERE c.id = $1
    LIMIT 1
    `,
    [camaraId]
  );
  return {
    capacidad_maxima: rows?.[0]?.capacidad_maxima ?? null,
    lugar_nombre: rows?.[0]?.lugar_nombre ?? null,
  };
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
    toEpochSec(b.timestamp); // útil si quieres depurar

    const client = await pool.connect();
    try {
      const camara_id = await getCamId(client, b.source_id);
      if (!camara_id) {
        return res
          .status(404)
          .json({ error: "camera_not_found", source_id: b.source_id });
      }

      // Columnas esperadas:
      // ts timestamptz, ts_sec int GENERATED, count int, unique_count int,
      // max_count int, min_count int, roll_avg float8, fps float8
      const q = `
        INSERT INTO metricas
          (camara_id, ts, count, unique_count, max_count, min_count, roll_avg, fps)
        VALUES
          ($1, $2::timestamptz, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (camara_id, ts_sec)
        DO UPDATE SET
          count        = EXCLUDED.count,
          unique_count = EXCLUDED.unique_count,
          max_count    = GREATEST(COALESCE(metricas.max_count, 0), COALESCE(EXCLUDED.max_count, 0)),
          min_count    = LEAST(COALESCE(metricas.min_count, EXCLUDED.min_count), EXCLUDED.min_count),
          roll_avg     = EXCLUDED.roll_avg,
          fps          = EXCLUDED.fps
        RETURNING id
      `;

      const params = [
        camara_id,            // $1
        b.timestamp,          // $2 (ISO con 'Z')
        b.count,              // $3
        b.unique ?? 0,        // $4
        b.max ?? null,        // $5
        b.min ?? null,        // $6
        b.avg_window ?? null, // $7
        b.fps ?? null,        // $8
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
 * Dashboard HTML (self-hosted JS)
 */
app.get("/", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8").send(DASH_HTML);
});

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

      // KPIs básicos
      const counts = rows.map((r) => Number(r.count || 0));
      const cNow = counts[counts.length - 1];
      const cMax = Math.max(...counts);
      const cMin = Math.min(...counts);
      const prom = counts.reduce((a, b) => a + b, 0) / Math.max(1, counts.length);

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

  
      const last = rows[rows.length - 1];

     
      const { capacidad_maxima, lugar_nombre } = await getLugarInfoByCam(client, camara_id);
      let capacidad_pct = null;
      let semaforo = null;
      let disponibles = null;
      if (Number.isFinite(cNow) && capacidad_maxima && capacidad_maxima > 0) {
        capacidad_pct = Math.min(100, Math.round((cNow / capacidad_maxima) * 100));
        disponibles = Math.max(0, capacidad_maxima - cNow);

    
        if (capacidad_pct <= 30) semaforo = "verde";
        else if (capacidad_pct < 70) semaforo = "amarillo";
        else semaforo = "rojo";
      }

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

        // NUEVO
        capacidad_maxima: capacidad_maxima ?? null,
        capacidad_pct,
        disponibles,
        semaforo,
        lugar_nombre, 
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
app.get('/api/lugares/status', async (_req, res) => {
  try {
    const client = await pool.connect();
    try {
      const q = `
        SELECT
          l.id, l.nombre, l.lat, l.lon, l.capacidad_maxima,
          c.id AS camara_id
        FROM lugares l
        LEFT JOIN camaras c ON c.lugar_id = l.id AND c.habilitada = true
        WHERE l.activo = true
      `;
      const { rows } = await client.query(q);
      const out = [];
      for (const r of rows) {
        let countNow = null;
        if (r.camara_id) {
          const m = await client.query(
            'SELECT count FROM metricas WHERE camara_id = $1 ORDER BY ts DESC LIMIT 1',
            [r.camara_id]
          );
          if (m.rowCount) countNow = Number(m.rows[0].count || 0);
        }
        let semaforo = null;
        if (r.capacidad_maxima && r.capacidad_maxima > 0 && countNow != null) {
          const pct = Math.min(100, Math.round((countNow / r.capacidad_maxima) * 100));
          if (pct <= 30) semaforo = 'verde';
          else if (pct < 70) semaforo = 'amarillo';
          else semaforo = 'rojo';
        }
        out.push({
          id: r.id,
          nombre: r.nombre,
          lat: Number(r.lat),
          lon: Number(r.lon),
          capacidad_maxima: r.capacidad_maxima,
          count_now: countNow,
          semaforo,
        });
      }
      res.json(out);
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/**
 * Snapshot proxy (opcional)
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
function signJwt(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET || 'dev', { expiresIn: '7d' });
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'no_token' });
  try {
    req.user = jwt.verify(h.slice(7), process.env.JWT_SECRET || 'dev');
    next();
  } catch {
    res.status(401).json({ error: 'bad_token' });
  }
}

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { nombre, apellido, email, password, tipo_usuario='trabajador' } = req.body || {};
    if (!email || !password || !nombre || !apellido) return res.status(400).json({ error: 'missing' });
    const client = await pool.connect();
    try {
      const dup = await client.query('SELECT 1 FROM public.usuarios_app WHERE email=$1 LIMIT 1', [email]);
      if (dup.rowCount) return res.status(409).json({ error: 'email_exists' });
      const hash = await bcrypt.hash(password, 10);
      const ins = await client.query(
        'INSERT INTO public.usuarios_app (nombre, apellido, email, password_hash, tipo_usuario) VALUES ($1,$2,$3,$4,$5) RETURNING id,nombre,apellido,email,tipo_usuario',
        [nombre, apellido, email, hash, tipo_usuario]
      );
      res.json({ ok: true, user: ins.rows[0] });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const client = await pool.connect();
    try {
      const q = await client.query('SELECT * FROM public.usuarios_app WHERE email=$1 AND eliminado=false', [email]);
      if (!q.rowCount) return res.status(401).json({ error: 'bad_credentials' });
      const u = q.rows[0];
      const ok = await bcrypt.compare(password, u.password_hash);
      if (!ok) return res.status(401).json({ error: 'bad_credentials' });
      const token = signJwt({ sub: u.id, email: u.email, tipo: u.tipo_usuario });
      res.json({
        token,
        user: { id: u.id, nombre: u.nombre, apellido: u.apellido, email: u.email, tipo_usuario: u.tipo_usuario }
      });
    } finally { client.release(); }
  } catch (e) { console.error(e); res.status(500).json({ error: 'server_error' }); }
});

// GET /api/users/me
app.get('/api/users/me', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const q = await client.query('SELECT id,nombre,apellido,email,tipo_usuario FROM public.usuarios_app WHERE id=$1', [req.user.sub]);
    if (!q.rowCount) return res.status(404).json({ error: 'not_found' });
    res.json(q.rows[0]);
  } finally { client.release(); }
});

// PUT /api/users/me
app.put('/api/users/me', authMiddleware, async (req, res) => {
  const { nombre, apellido, tipo_usuario } = req.body || {};
  const client = await pool.connect();
  try {
    const q = await client.query(
      'UPDATE public.usuarios_app SET nombre=COALESCE($1,nombre), apellido=COALESCE($2,apellido), tipo_usuario=COALESCE($3,tipo_usuario), updated_at=now() WHERE id=$4 RETURNING id,nombre,apellido,email,tipo_usuario',
      [nombre, apellido, tipo_usuario, req.user.sub]
    );
    res.json(q.rows[0]);
  } finally { client.release(); }
});


app.post("/reset", async (req, res) => {
  try {
    if (!ADMIN_KEY || req.headers["x-admin-key"] !== ADMIN_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }
    const source_id = String(req.body?.source_id || "");
    const minutes = Math.max(
      1,
      Math.min(60 * 6, Number(req.body?.minutes || 10))
    );

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

// ====== HTML del dashboard (self-hosted scripts) ======
const DASH_HTML = `<!DOCTYPE html>
<html lang="es"
      data-source="${(DEFAULT_SOURCE_ID || "").replace(/"/g,'&quot;')}"
      data-minutes="${Number(METRICS_WINDOW_MIN)}"
      data-has-reset="${ADMIN_KEY ? "1" : "0"}">
<head>
<meta charset="utf-8"><title>Dashboard Migratio out </title>
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
  /* Semáforo estilos */
  .sf-verde    { background:#0f5132; color:#d1e7dd; border-color:#0f5132; }
  .sf-amarillo { background:#664d03; color:#fff3cd; border-color:#664d03; }
  .sf-rojo     { background:#842029; color:#f8d7da; border-color:#842029; }

  .row { display:grid; grid-template-columns:1.5fr .9fr; gap:12px; margin-top:12px }
  #chart { background:#0b0f14; border-radius:10px; border:1px solid var(--border); }
  .snapshot { width:100%; border-radius:10px; border:1px solid var(--border); background:#0b0f14; height:360px; object-fit:contain }
  .actions { display:flex; gap:10px; margin-top:8px }
  button { background:#173045; color:#d7e6f2; border:1px solid var(--border); padding:8px 12px; border-radius:10px; cursor:pointer; }
</style>
</head><body>
  <header><h1>Dashboard Migratio Out (en vivo)</h1></header>
  <div class="container">
    <div class="grid">
      <div class="card kpi"><h2>Lugar</h2><div class="val" id="lugar_nombre">—</div></div>
      <div class="card kpi"><h2>Activos</h2><div class="val" id="activos">0</div></div>
      <div class="card kpi"><h2>Peak(Max)</h2><div class="val"><span id="max">0</span></div><div class="meta" id="max_time">—</div></div>

      <div class="card kpi"><h2>FPS</h2><div class="val" id="fps">0</div></div>
  
    
      <div class="card kpi">
        <h2>Total</h2>
        <div class="val" id="oc_pct">—</div>
        <div class="meta">
          <span id="oc_sem" class="chip">—</span>
          <span id="capmax" class="chip">cap: —</span>
          <span id="disp"   class="chip">disp: —</span>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="card">
        <h3 class="panel-title">Serie temporal (últimos minutos) <span class="chip" id="ts">—</span> <span class="chip" id="trend"></span></h3>
        <canvas id="chart" width="1000" height="360" style="display:block"></canvas>
        <div class="actions"><button id="resetBtn">Reset métricas</button></div>
      </div>

    </div>
  </div>

  <!-- Self-hosted scripts (mismo origen) -->
  <script src="/vendor/chart.umd.min.js" defer></script>
  <script src="/static/dashboard.js" defer></script>
</body></html>`;
