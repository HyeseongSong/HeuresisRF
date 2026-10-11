// server.ts
import type { ServerWebSocket } from "bun";
import { sql } from "drizzle-orm";
import { db } from "./lib/db";
import { incidentVerdicts } from "./lib/schema";
import { POSSignalTracker, parseHardwarePayload } from "./tracker";
import { evaluateWithAgent } from "./agent";
import type { RawHardwarePayload, WSData } from "./types";

const WS_PORT = 3001;

const tracker = new POSSignalTracker();
let activeIngestConnections = 0;
const connectedIngestDevices = new Map<string, number>();
const activeEvaluations = new Set<string>();

// Track live physical security state per device in memory
const deviceSecurityState = new Map<string, "SECURE" | "COMPROMISED">();

let incidentSeq = 0;

try {
  const existing = await db.select().from(incidentVerdicts);
  if (existing.length > 0) {
    incidentSeq = Math.max(0, ...existing.map((r) => Number(r.id) || 0));
    await db.execute(
      sql`SELECT setval(pg_get_serial_sequence('incident_verdicts', 'id'), ${incidentSeq}, true)`
    );
  } else {
    incidentSeq = 0;
    await db.execute(
      sql`SELECT setval(pg_get_serial_sequence('incident_verdicts', 'id'), 1, false)`
    );
  }
  console.log(`[WS BACKEND] Seeded incident ID sequence at: ${incidentSeq}`);
} catch (e) {
  console.warn("[WS BACKEND] Could not sync initial incident sequence with DB:", e);
}

let server = Bun.serve<WSData>({
  port: WS_PORT,
  hostname: "0.0.0.0",

  fetch(req, server) {
    const url = new URL(req.url);

    if (url.pathname === "/ingest" || url.pathname === "/egress") {
      const type = url.pathname === "/ingest" ? "INGEST" : "EGRESS";
      const upgraded = server.upgrade(req, { data: { type, connectedAt: Date.now() } });
      if (upgraded) return undefined;
      return new Response(`WebSocket Upgrade Failed (${url.pathname})`, { status: 400 });
    }

    return new Response("Not Found", { status: 404 });
  },

  websocket: {
    async open(ws: ServerWebSocket<WSData>) {
      if (ws.data.type === "EGRESS") {
        ws.subscribe("dashboard-feed");

        const activeList = Array.from(connectedIngestDevices.keys());
        const primaryDevice = activeList[0] ?? "pos_terminal_01";

        // 1. Send live ingestion status
        if (activeIngestConnections > 0) {
          ws.send(
            JSON.stringify({
              event: "INGEST_STATUS_CHANGE",
              status: "ONLINE",
              deviceId: primaryDevice,
              activeDevices: activeList,
              activeIngestCount: activeIngestConnections,
              timestamp: Number((Date.now() / 1000).toFixed(2)),
            })
          );
        }

        // 2. Fetch all historical incident alerts and replay chronologically
        try {
          const records = await db.select().from(incidentVerdicts);
          records.sort((a, b) => Number(a.id) - Number(b.id));

          ws.cork(() => {
            for (const record of records) {
              if (record.classification === "SECURE_RECOVERED") continue;

              const recordTimestamp = (record as any).createdAt
                ? Number((new Date((record as any).createdAt).getTime() / 1000).toFixed(2))
                : Number((Date.now() / 1000).toFixed(2));

              ws.send(
                JSON.stringify({
                  event: "INCIDENT_ALERT",
                  incidentId: Number(record.id),
                  deviceId: record.deviceId,
                  timestamp: recordTimestamp,
                  status: "COMPROMISED",
                  isReplay: true, // Tag as historical record
                  verdict: {
                    threat_type: record.classification,
                    confidence: record.confidence != null ? Number(record.confidence) : undefined,
                    rationale: record.rationale,
                    action: record.actionTaken,
                  },
                })
              );
            }

            // 3. Sync client with the CURRENT in-memory state of the terminal
            const currentState = deviceSecurityState.get(primaryDevice) ?? "SECURE";
            if (currentState === "SECURE") {
              ws.send(
                JSON.stringify({
                  event: "STATUS_RECOVERED",
                  deviceId: primaryDevice,
                  status: "SECURE",
                  reason: "SUSTAINED_BASELINE",
                  timestamp: Number((Date.now() / 1000).toFixed(2)),
                })
              );
            }
          });
        } catch (dbErr) {
          console.error("[Postgres Egress History Read Error]:", dbErr);
        }

        return;
      }

      activeIngestConnections++;
      server.publish(
        "dashboard-feed",
        JSON.stringify({
          event: "INGEST_STATUS_CHANGE",
          status: "ONLINE",
          activeIngestCount: activeIngestConnections,
          timestamp: Number((Date.now() / 1000).toFixed(2)),
        })
      );
    },

    async message(ws: ServerWebSocket<WSData>, message: string | Buffer) {
      if (ws.data.type !== "INGEST") return;

      try {
        const raw: RawHardwarePayload =
          typeof message === "string" ? JSON.parse(message) : JSON.parse(message.toString());
        const payload = parseHardwarePayload(raw);
        if (!payload) return;

        if (!ws.data.deviceId) {
          ws.data.deviceId = payload.deviceId;
          const count = connectedIngestDevices.get(payload.deviceId) ?? 0;
          connectedIngestDevices.set(payload.deviceId, count + 1);

          server.publish(
            "dashboard-feed",
            JSON.stringify({
              event: "INGEST_STATUS_CHANGE",
              status: "ONLINE",
              deviceId: payload.deviceId,
              activeIngestCount: activeIngestConnections,
              timestamp: Number((Date.now() / 1000).toFixed(2)),
            })
          );
        } else if (ws.data.deviceId !== payload.deviceId) {
          return;
        }

        server.publish(
          "dashboard-feed",
          JSON.stringify({
            event: "TELEMETRY_POINT",
            deviceId: payload.deviceId,
            rssi: payload.rssi,
            spectrum: raw.spectrum ?? {},
            fft: payload.fft,
            timestamp: payload.timestamp,
          })
        );

        const result = tracker.processReading(payload);
        if (!result) return;

        // Transition: Terminal baseline recovered
        if (result.kind === "RECOVERED") {
          activeEvaluations.delete(result.deviceId);
          deviceSecurityState.set(result.deviceId, "SECURE");

          server.publish(
            "dashboard-feed",
            JSON.stringify({
              event: "STATUS_RECOVERED",
              deviceId: result.deviceId,
              status: "SECURE",
              reason: "SUSTAINED_BASELINE",
              rssi: payload.rssi,
              timestamp: result.recoveryTimestamp,
            })
          );
          return;
        }

        const { metrics } = result;
        deviceSecurityState.set(metrics.deviceId, "COMPROMISED");

        server.publish(
          "dashboard-feed",
          JSON.stringify({
            event: "HEURISTIC_ALERT_TRIGGERED",
            deviceId: metrics.deviceId,
            timestamp: payload.timestamp,
            status: "COMPROMISED",
            heuristic: {
              likelyType: metrics.likelyType,
              isAttenuationBreach: metrics.isAttenuationBreach,
              meanRssi: metrics.meanRssi,
              variance: metrics.variance,
              deltaDb: metrics.deltaDb,
              powerSurgeRatio: metrics.powerSurgeRatio,
              dominantHarmonic: {
                binIndex: metrics.spectral.peakBinIndex,
                powerDbm: metrics.spectral.peakBinPower,
                spectralSpreadDb: metrics.spectral.spectralSpreadDb,
                isNarrowbandSpike: metrics.spectral.isNarrowbandSpike,
              },
              fft: metrics.spectral.bins,
              sampleCount: metrics.sampleCount,
              durationSec: metrics.durationSec,
            },
          })
        );

        if (activeEvaluations.has(metrics.deviceId)) return;
        activeEvaluations.add(metrics.deviceId);

        try {
          const verdict = await evaluateWithAgent(metrics);
          if (verdict.threat_type === "FALSE_POSITIVE") {
            deviceSecurityState.set(metrics.deviceId, "SECURE");
          } else {
            deviceSecurityState.set(metrics.deviceId, "COMPROMISED");
          }
          let incidentId = ++incidentSeq;

          try {
            const [record] = await db
              .insert(incidentVerdicts)
              .values({
                deviceId: metrics.deviceId,
                classification: verdict.threat_type,
                confidence: verdict.confidence,
                meanRssi: metrics.meanRssi,
                variance: metrics.variance,
                sampleCount: metrics.sampleCount,
                rationale: verdict.rationale,
                actionTaken: verdict.action,
                rawSeries: JSON.stringify(metrics.rawSeries),
              })
              .returning();

            if (record?.id != null) {
              incidentId = Number(record.id);
              incidentSeq = Math.max(incidentSeq, incidentId);
            }
          } catch (dbErr) {
            console.error("[Postgres Incident Write Error]:", dbErr);
          }

          server.publish(
            "dashboard-feed",
            JSON.stringify({
              event: "INCIDENT_ALERT",
              incidentId,
              deviceId: metrics.deviceId,
              timestamp: Number((Date.now() / 1000).toFixed(2)),
              status: "COMPROMISED",
              verdict,
            })
          );
        } finally {
          activeEvaluations.delete(metrics.deviceId);
        }
      } catch (err) {
        console.error("[Telemetry Ingest Error]:", err);
      }
    },

    close(ws: ServerWebSocket<WSData>) {
      if (ws.data.type === "EGRESS") {
        ws.unsubscribe("dashboard-feed");
        return;
      }

      activeIngestConnections = Math.max(0, activeIngestConnections - 1);

      if (ws.data.deviceId) {
        const count = connectedIngestDevices.get(ws.data.deviceId) ?? 1;
        if (count <= 1) {
          connectedIngestDevices.delete(ws.data.deviceId);
        } else {
          connectedIngestDevices.set(ws.data.deviceId, count - 1);
        }
      }

      server.publish(
        "dashboard-feed",
        JSON.stringify({
          event: "INGEST_STATUS_CHANGE",
          status: activeIngestConnections > 0 ? "ONLINE" : "OFFLINE",
          deviceId: ws.data.deviceId ?? "unknown",
          activeIngestCount: activeIngestConnections,
          timestamp: Number((Date.now() / 1000).toFixed(2)),
        })
      );
    },
  },
});

console.log(`> Bun WebSocket service listening on ws://0.0.0.0:${WS_PORT}`);