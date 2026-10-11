import next from "next";
import type { ServerWebSocket } from "bun";
import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { db } from "./lib/db";
import { incidentVerdicts } from "./lib/schema";
import { POSSignalTracker, parseHardwarePayload } from "./tracker";
import { evaluateWithAgent } from "./agent";
import type { RawHardwarePayload, WSData } from "./types";

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev });
const handle = app.getRequestHandler();
const PORT = parseInt(process.env.PORT || "3000", 10);

await app.prepare();

const tracker = new POSSignalTracker();
let activeIngestConnections = 0;
const connectedIngestDevices = new Map<string, number>();
const activeEvaluations = new Set<string>();

function forwardToNext(req: Request): Promise<Response> {
  const url = new URL(req.url);

  return new Promise<Response>((resolve) => {
    const socket = new Socket();
    const nodeReq = new IncomingMessage(socket);

    nodeReq.url = url.pathname + url.search;
    nodeReq.method = req.method;

    req.headers.forEach((val, key) => {
      const lower = key.toLowerCase();
      // Prevent Next.js from gzipping the internal stream; Bun handles compression natively.
      if (lower !== "accept-encoding") {
        nodeReq.headers[lower] = val;
      }
    });

    if (req.body) {
      const reader = req.body.getReader();
      (async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) {
              nodeReq.push(null);
              break;
            }
            nodeReq.push(Buffer.from(value));
          }
        } catch (err) {
          nodeReq.destroy(err instanceof Error ? err : new Error(String(err)));
        }
      })();
    } else {
      nodeReq.push(null);
    }

    const nodeRes = new ServerResponse(nodeReq);

    let responseResolved = false;
    let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;

    const cleanup = () => {
      if (!socket.destroyed) {
        socket.destroy();
      }
    };

    const flushHeadersAndStartStream = () => {
      if (responseResolved) return;
      responseResolved = true;

      const headers = new Headers();
      const rawHeaders = nodeRes.getHeaders();
      for (const [key, val] of Object.entries(rawHeaders)) {
        if (val === undefined || val === null) continue;
        const lowerKey = key.toLowerCase();

        // Omit hop-by-hop and chunk/length headers that interfere with streaming fetch responses
        if (
          lowerKey === "transfer-encoding" ||
          lowerKey === "content-encoding" ||
          lowerKey === "content-length"
        ) {
          continue;
        }

        if (Array.isArray(val)) {
          val.forEach((v) => headers.append(key, String(v)));
        } else {
          headers.set(key, String(val));
        }
      }

      const readable = new ReadableStream<Uint8Array>({
        start(controller) {
          streamController = controller;
        },
        cancel() {
          cleanup();
        },
      });

      resolve(
        new Response(readable, {
          status: nodeRes.statusCode || 200,
          statusText: nodeRes.statusMessage || "OK",
          headers,
        })
      );
    };

    const toBuffer = (chunk: any, encoding?: any): Uint8Array => {
      if (Buffer.isBuffer(chunk)) return chunk;
      if (typeof chunk === "string") {
        return Buffer.from(
          chunk,
          (typeof encoding === "string" ? encoding : undefined) as BufferEncoding
        );
      }
      return Buffer.from(chunk);
    };

    const origWriteHead = nodeRes.writeHead.bind(nodeRes);
    (nodeRes as any).writeHead = (...args: any[]) => {
      const res = (origWriteHead as Function)(...args);
      flushHeadersAndStartStream();
      return res;
    };

    nodeRes.flushHeaders = () => {
      flushHeadersAndStartStream();
    };

    nodeRes.write = (chunk: any, encoding?: any, cb?: any) => {
      flushHeadersAndStartStream();
      if (chunk && streamController) {
        streamController.enqueue(toBuffer(chunk, encoding));
      }
      if (typeof encoding === "function") encoding();
      if (typeof cb === "function") cb();
      return true;
    };

    nodeRes.end = (chunk?: any, encoding?: any, cb?: any) => {
      flushHeadersAndStartStream();
      if (chunk && streamController) {
        streamController.enqueue(toBuffer(chunk, encoding));
      }

      if (streamController) {
        try {
          streamController.close();
        } catch {}
      }

      cleanup();
      if (typeof encoding === "function") encoding();
      if (typeof cb === "function") cb();
      return nodeRes;
    };

    nodeRes.on("finish", cleanup);
    nodeRes.on("close", cleanup);
    socket.on("error", cleanup);

    handle(nodeReq, nodeRes).catch((err) => {
      console.error("[Next.js Render Error]:", err);
      cleanup();
      if (!responseResolved) {
        resolve(new Response("Internal Server Error", { status: 500 }));
      } else if (streamController) {
        try {
          streamController.error(err);
        } catch {}
      }
    });
  });
}

Bun.serve<WSData>({
  port: PORT,
  hostname: "0.0.0.0",

  fetch(req, server) {
    const url = new URL(req.url);

    if (url.pathname === "/ingest" || url.pathname === "/egress") {
      const type = url.pathname === "/ingest" ? "INGEST" : "EGRESS";
      const upgraded = server.upgrade(req, { data: { type, connectedAt: Date.now() } });
      if (upgraded) return undefined;
      return new Response(`WebSocket Upgrade Failed (${url.pathname})`, { status: 400 });
    }

    return forwardToNext(req);
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
      ws.publish(
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

          ws.publish(
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

        ws.publish(
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

          ws.publish(
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
        ws.publish(
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

          ws.publish(
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

      ws.publish(
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

console.log(`> Bun runtime active on http://0.0.0.0:${PORT}`);