// server.ts
import type { ServerWebSocket } from "bun";
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

let server = Bun.serve<WSData>({
  port: WS_PORT,
  hostname: "0.0.0.0",

  fetch(req, server) {
    const url = new URL(req.url);

    if (url.pathname === "/ingest" || url.pathname === "/egress") {
      console.log(`[WS BACKEND] Upgrade request received for: ${url.pathname}`);
      const type = url.pathname === "/ingest" ? "INGEST" : "EGRESS";
      const upgraded = server.upgrade(req, { data: { type, connectedAt: Date.now() } });
      console.log(`[WS BACKEND] Upgrade result: ${upgraded}`);
      if (upgraded) return undefined;
      return new Response(`WebSocket Upgrade Failed (${url.pathname})`, { status: 400 });
    }

    return new Response("Not Found", { status: 404 });
  },

  websocket: {
    open(ws: ServerWebSocket<WSData>) {
      if (ws.data.type === "EGRESS") {
        ws.subscribe("dashboard-feed");
        if (activeIngestConnections > 0) {
          const activeList = Array.from(connectedIngestDevices.keys());
          ws.send(
            JSON.stringify({
              event: "INGEST_STATUS_CHANGE",
              status: "ONLINE",
              deviceId: activeList[0] ?? null,
              activeDevices: activeList,
              activeIngestCount: activeIngestConnections,
              timestamp: Number((Date.now() / 1000).toFixed(2)),
            })
          );
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

        if (result.kind === "RECOVERED") {
          activeEvaluations.delete(result.deviceId);
          let recoveryId = Date.now();

          try {
            const [recoveryRecord] = await db
              .insert(incidentVerdicts)
              .values({
                deviceId: result.deviceId,
                classification: "SECURE_RECOVERED",
                confidence: 1.0,
                meanRssi: payload.rssi,
                variance: 0.0,
                sampleCount: 0,
                rationale:
                  "RF physical emissions stabilized within safe baseline bounds for > 2.0s. Terminal unlocked.",
                actionTaken: "RESTORE_NORMAL",
                rawSeries: JSON.stringify([]),
              })
              .returning();

            if (recoveryRecord?.id) recoveryId = recoveryRecord.id;
          } catch (dbErr) {
            console.error("[Postgres Recovery Write Error]:", dbErr);
          }

          server.publish(
            "dashboard-feed",
            JSON.stringify({
              event: "STATUS_RECOVERED",
              incidentId: recoveryId,
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

        if (activeEvaluations.has(metrics.deviceId)) {
          return;
        }

        activeEvaluations.add(metrics.deviceId);

        try {
          const verdict = await evaluateWithAgent(metrics);
          let incidentId = Date.now();

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

            if (record?.id) incidentId = record.id;
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