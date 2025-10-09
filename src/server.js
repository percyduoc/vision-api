import "dotenv/config";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import { Pool } from "pg";
import { z } from "zod";

const app = express();
app.use(helmet());
app.use(cors());      // en producción limita origins
app.use(express.json());
app.use(morgan("tiny"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false
});
const API_KEY = process.env.API_KEY || "supersecreto";

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

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/api/metrics", async (req, res) => {
  try {
    if ((req.headers.authorization || "") !== `Bearer ${API_KEY}`)
      return res.status(401).json({ error: "unauthorized" });

    const b = Payload.parse(req.body);
    const client = await pool.connect();
    try {
      const cam = await client.query(
        "SELECT id FROM camaras WHERE codigo = $1 LIMIT 1",
        [b.source_id]
      );
      if (cam.rowCount === 0)
        return res.status(404).json({ error: "camera_not_found", source_id: b.source_id });

      const camara_id = cam.rows[0].id;

      const q = `
        INSERT INTO metricas (camara_id, ts, count, unique_count, max_count, min_count, roll_avg, fps)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (camara_id, ts_sec)
        DO UPDATE SET
          count = EXCLUDED.count,
          unique_count = EXCLUDED.unique_count,
          max_count = GREATEST(COALESCE(metricas.max_count,0), COALESCE(EXCLUDED.max_count,0)),
          min_count = LEAST(COALESCE(metricas.min_count, EXCLUDED.min_count), EXCLUDED.min_count),
          roll_avg = EXCLUDED.roll_avg,
          fps = EXCLUDED.fps
        RETURNING id`;
      const params = [
        camara_id,
        b.timestamp,
        b.count,
        b.unique ?? 0,
        b.max ?? null,
        b.min ?? null,
        b.avg_window ?? null,
        b.fps ?? null
      ];

      const { rows } = await client.query(q, params);
      res.json({ ok: true, id: rows[0].id });
    } finally {
      client.release();
    }
  } catch (e) {
    if (e instanceof z.ZodError) return res.status(400).json({ error: "bad_payload", issues: e.issues });
    console.error(e);
    res.status(500).json({ error: "server_error" });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`API up on :${process.env.PORT || 3000}`);
});
