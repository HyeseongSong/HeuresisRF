// server.ts
import next from "next";
import type { ServerWebSocket } from "bun";
import { Readable, Writable } from "node:stream";
import { db } from "./lib/db";
import { incidentVerdicts } from "./lib/schema";
import { parseHardwarePayload, RawHardwarePayload } from "./lib/adapter";

// ---------------------------------------------------------------------------
// Types & Domain Enums
// ---------------------------------------------------------------------------

export type ProcessResult =
  | {
      kind: "RECOVERED";
      deviceId: string;
      recoveryTimestamp: number;
    }
  | {
      kind: "ALERT";
      deviceId: string;
      metrics: WindowMetrics;
    };

export type ThreatType =
  | "SNIFFING_TAP"
  | "DATA_EXFIL_BEACON"
  | "COMMUNICATION_JAMMING"
  | "FALSE_POSITIVE";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type ContainmentAction =
  | "LOCK_TERMINAL"
  | "ISOLATE_OFFLINE"
  | "FLAG_FOR_INSPECTION"
  | "IGNORE";

export interface POSTelemetryPayload {
  device_id: string;
  rssi: number;
  timestamp: number; // Float epoch seconds (e.g. 1728568800.12)
  fft: number[]; // 8-point FFT spectral power values in dBm
}

export interface RSSIPoint {
  t: number;
  rssi: number;
}

export interface SpectralAnalysis {
  bins: number[];
  peakBinIndex: number;
  peakBinPower: number;
  spectralSpreadDb: number; // Peak bin power relative to adjacent floor
  isNarrowbandSpike: boolean;
}

export interface WindowMetrics {
  deviceId: string;
  sampleCount: number;
  meanRssi: number;
  variance: number;
  minRssi: number;
  maxRssi: number;
  medianIntervalMs: number;
  intervalStdDevMs: number;
  durationSec: number;
  deltaDb: number;
  powerSurgeRatio: number;
  likelyType: ThreatType;
  rawSeries: RSSIPoint[];
  spectral: SpectralAnalysis;
}

export interface AgentVerdict {
  threat_type: ThreatType;
  compromised_vector: string;
  risk_level: RiskLevel;
  risk_justification: string;
  pci_containment_action: string;
  action: ContainmentAction;
  confidence: number;
  threat_diagnosis: string[];
  rationale: string;
}

interface WSData {
  type: "INGEST" | "EGRESS";
  deviceId?: string;
  connectedAt: number;
}

// ---------------------------------------------------------------------------
// State-Latched Hardware Bounds & Spectral Analyzer Engine
// ---------------------------------------------------------------------------

// server.ts (Updated POSSignalTracker with Temporal Persistence & Carrier Stability)

interface BreachCandidate {
  consecutiveCount: number;
  firstBreachTimestamp: number;
  peakBins: number[];
}

class POSSignalTracker {
  private windows = new Map<string, RSSIPoint[]>();
  private terminalStates = new Map<string, "SECURE" | "COMPROMISED">();
  private recoveryTimestamps = new Map<string, number>();
  
  // Tracks candidate breach frames to filter out non-persistent transient spikes
  private breachCandidates = new Map<string, BreachCandidate>();

  private readonly WINDOW_SECONDS = 3.0;
  private readonly MIN_SAMPLES = 4;

  // Physical-layer bounds (dBm)
  private readonly P_MAX = -38.0; 
  private readonly P_MIN = -82.0; 
  private readonly RECOVERY_REQUIRED_SEC = 2.0;

  // Transient suppression thresholds
  // 3 consecutive frames @ 10 Hz = 300 ms of sustained RF emission
  private readonly REQUIRED_CONSECUTIVE_BREACHES = 3; 

  private analyzeFFT(fft: number[]): SpectralAnalysis {
    const bins = Array.isArray(fft) && fft.length === 8 ? fft : Array(8).fill(-65.0);
    let peakIndex = 0;
    let maxVal = -Infinity;

    for (let i = 0; i < bins.length; i++) {
      if (bins[i] > maxVal) {
        maxVal = bins[i];
        peakIndex = i;
      }
    }

    const otherBins = bins.filter((_, idx) => idx !== peakIndex);
    const avgOther =
      otherBins.length > 0
        ? otherBins.reduce((a, b) => a + b, 0) / otherBins.length
        : maxVal;
    const spectralSpread = Number((maxVal - avgOther).toFixed(2));
    const isNarrowbandSpike = spectralSpread >= 18.0;

    return {
      bins,
      peakBinIndex: peakIndex,
      peakBinPower: Number(maxVal.toFixed(2)),
      spectralSpreadDb: spectralSpread,
      isNarrowbandSpike,
    };
  }

  public processReading(payload: POSTelemetryPayload): ProcessResult | null {
    const { device_id, rssi, timestamp } = payload;
    const cutoff = timestamp - this.WINDOW_SECONDS;

    // 1. Sliding ring buffer
    let series = this.windows.get(device_id) ?? [];
    series = series.filter((pt) => pt.t >= cutoff);
    series.push({ t: timestamp, rssi });
    this.windows.set(device_id, series);

    if (series.length < this.MIN_SAMPLES) {
      return null;
    }

    // 2. Rolling mean across last 3 samples (~300 ms at 10 Hz)
    const recentWindow = series.slice(-3);
    const recentRssiVals = recentWindow.map((s) => s.rssi);
    const currentMeanRssi =
      recentRssiVals.reduce((acc, val) => acc + val, 0) / recentRssiVals.length;

    // 3. Spectral analysis (8 macro-bins)
    const spectral = this.analyzeFFT(payload.fft);

    // 4. Hardware bounds evaluation
    const isWidebandUpperBreach = currentMeanRssi > this.P_MAX;
    const isNarrowbandUpperBreach = spectral.peakBinPower > this.P_MAX && spectral.isNarrowbandSpike;
    const isUpperBreach = isWidebandUpperBreach || isNarrowbandUpperBreach;
    const isLowerBreach = currentMeanRssi < this.P_MIN;
    const isBreached = isUpperBreach || isLowerBreach;

    const currentState = this.terminalStates.get(device_id) ?? "SECURE";

    // -------------------------------------------------------------
    // LATCH LOGIC & RECOVERY (While already COMPROMISED)
    // -------------------------------------------------------------
    if (currentState === "COMPROMISED") {
      if (!isBreached) {
        const firstSafeTime = this.recoveryTimestamps.get(device_id) ?? timestamp;
        this.recoveryTimestamps.set(device_id, firstSafeTime);

        if (timestamp - firstSafeTime >= this.RECOVERY_REQUIRED_SEC) {
          this.terminalStates.set(device_id, "SECURE");
          this.recoveryTimestamps.delete(device_id);
          this.breachCandidates.delete(device_id);

          return {
            kind: "RECOVERED",
            deviceId: device_id,
            recoveryTimestamp: timestamp,
          };
        }
      } else {
        this.recoveryTimestamps.delete(device_id);
      }
      return null;
    }

    // -------------------------------------------------------------
    // TRANSIENT SPIKE FILTERING (While SECURE)
    // -------------------------------------------------------------
    if (!isBreached) {
      // Signal is clean: immediately reset transient candidate tracker
      this.breachCandidates.delete(device_id);
      this.recoveryTimestamps.delete(device_id);
      return null;
    }

    // A breach occurred. Track persistence and carrier stability
    const candidate = this.breachCandidates.get(device_id) ?? {
      consecutiveCount: 0,
      firstBreachTimestamp: timestamp,
      peakBins: [],
    };

    candidate.consecutiveCount += 1;
    candidate.peakBins.push(spectral.peakBinIndex);
    this.breachCandidates.set(device_id, candidate);

    // Filter Condition 1: Check Temporal Persistence
    if (candidate.consecutiveCount < this.REQUIRED_CONSECUTIVE_BREACHES) {
      // Suppress alert until breach proves sustained (under 300 ms)
      return null;
    }

    // Filter Condition 2: Harmonic Carrier Stability (for Narrowband Shimmers)
    // If breach was triggered by a narrowband spike, verify the harmonic bin didn't bounce
    if (isNarrowbandUpperBreach) {
      const recentBins = candidate.peakBins.slice(-this.REQUIRED_CONSECUTIVE_BREACHES);
      const isCarrierStable = recentBins.every((bin) => bin === recentBins[0]);

      if (!isCarrierStable) {
        // Frequency hopped between bins during the burst -> transient wideband emitter/phone
        this.breachCandidates.delete(device_id);
        return null;
      }
    }

    // -------------------------------------------------------------
    // ATTACK CONFIRMED: TRANSITION SECURE -> COMPROMISED
    // -------------------------------------------------------------
    this.terminalStates.set(device_id, "COMPROMISED");
    this.breachCandidates.delete(device_id);
    this.recoveryTimestamps.delete(device_id);

    // 5. Extract forensic metrics
    const rssiVals = series.map((s) => s.rssi);
    const meanRssi = rssiVals.reduce((acc, val) => acc + val, 0) / rssiVals.length;
    const variance =
      rssiVals.reduce((acc, val) => acc + Math.pow(val - meanRssi, 2), 0) /
      rssiVals.length;

    const intervals: number[] = [];
    for (let i = 1; i < series.length; i++) {
      intervals.push(Math.round((series[i].t - series[i - 1].t) * 1000));
    }
    intervals.sort((a, b) => a - b);
    const medianInterval =
      intervals.length > 0 ? intervals[Math.floor(intervals.length / 2)] : 0;

    const meanInterval =
      intervals.reduce((acc, val) => acc + val, 0) / (intervals.length || 1);
    const intervalVariance =
      intervals.reduce((acc, val) => acc + Math.pow(val - meanInterval, 2), 0) /
      (intervals.length || 1);
    const intervalStdDev = Math.sqrt(intervalVariance);

    const durationSec = series[series.length - 1].t - series[0].t;
    const effectivePowerDbm = Math.max(currentMeanRssi, spectral.peakBinPower);
    const deltaDb = Number((effectivePowerDbm - this.P_MAX).toFixed(2));
    const powerSurgeRatio =
      deltaDb > 0 ? Number(Math.pow(10, deltaDb / 10).toFixed(1)) : 1.0;

    let likelyType: ThreatType = "FALSE_POSITIVE";
    if (isLowerBreach) {
      likelyType = "COMMUNICATION_JAMMING";
    } else if (variance > 14.0 && !spectral.isNarrowbandSpike) {
      likelyType = "FALSE_POSITIVE";
    } else if (spectral.isNarrowbandSpike && effectivePowerDbm >= this.P_MAX) {
      likelyType = "SNIFFING_TAP";
    } else if (intervalStdDev < 80 && series.length >= 5) {
      likelyType = "DATA_EXFIL_BEACON";
    } else if (isUpperBreach) {
      likelyType = "COMMUNICATION_JAMMING";
    }

    return {
      kind: "ALERT",
      deviceId: device_id,
      metrics: {
        deviceId: device_id,
        sampleCount: series.length,
        meanRssi: Number(currentMeanRssi.toFixed(2)),
        variance: Number(variance.toFixed(2)),
        minRssi: Math.min(...rssiVals),
        maxRssi: Math.max(...rssiVals),
        medianIntervalMs: medianInterval,
        intervalStdDevMs: Math.round(intervalStdDev),
        durationSec: Number(durationSec.toFixed(2)),
        deltaDb,
        powerSurgeRatio,
        likelyType,
        rawSeries: [...series],
        spectral,
      },
    };
  }

  public manualReset(deviceId: string) {
    this.terminalStates.set(deviceId, "SECURE");
    this.recoveryTimestamps.delete(deviceId);
    this.breachCandidates.delete(deviceId);
    this.windows.delete(deviceId);
    console.log(`[MANUAL OVERRIDE] Lockout cleared for terminal: ${deviceId}`);
  }
}

const tracker = new POSSignalTracker();

// ---------------------------------------------------------------------------
// PCI Forensic Fallback Engine
// ---------------------------------------------------------------------------

export function createFallbackVerdict(
  threat: ThreatType,
  deltaDb: number,
  powerSurge: number,
  spectral?: SpectralAnalysis
): AgentVerdict {
  const peakBinStr = spectral
    ? `Bin ${spectral.peakBinIndex} @ ${spectral.peakBinPower} dBm (+${spectral.spectralSpreadDb} dB spread)`
    : "48.78 MHz Harmonic";

  if (threat === "SNIFFING_TAP") {
    return {
      threat_type: "SNIFFING_TAP",
      compromised_vector:
        "ISO/IEC 7816-3 Smart Card Interface (Tapped I/O line radiating 48.78 MHz harmonics)",
      risk_level: "CRITICAL",
      risk_justification:
        "Direct exfiltration of unencrypted chip Track-2 equivalent data and plaintext offline PIN violating PCI PTS v6.0 Section B1.",
      pci_containment_action:
        "Invalidate active transaction cryptogram (ARQC), trigger remote DUKPT Future Key zeroization, and place terminal into tamper-lockout.",
      action: "LOCK_TERMINAL",
      confidence: 0.98,
      threat_diagnosis: [
        "Parasitic transmitter coupling detected on smart card I/O bus lines[cite: 1, 4]",
        "EMV chip slot physical trace tapped via invasive shimmer overlay[cite: 1]",
        `Observed +${deltaDb} dB surge (~${powerSurge}x baseline power) concentrated on ${peakBinStr}[cite: 7]`,
      ],
      rationale: `Upper RF bound breach detected (+${deltaDb} dB / ~${powerSurge}x power surge). Parasitic transmitter coupling on smart card I/O bus lines.`,
    };
  }

  if (threat === "DATA_EXFIL_BEACON") {
    return {
      threat_type: "DATA_EXFIL_BEACON",
      compromised_vector: "433 MHz / 2.4 GHz Secondary Transmitter Trace[cite: 2]",
      risk_level: "HIGH",
      risk_justification:
        "Periodic automated packet offload detected; violating PCI DSS v4.0 Req 9.9 physical tamper monitoring requirements.",
      pci_containment_action:
        "Sever local gateway connectivity, isolate terminal from LAN routing, and quarantine device identity.",
      action: "ISOLATE_OFFLINE",
      confidence: 0.92,
      threat_diagnosis: [
        "Consistent inter-packet interval timing detected (low timing variance)",
        "Automated wireless beaconing exfiltration signature identified",
        "Probable batch transmission of queued cardholder account data",
      ],
      rationale:
        "Low-interval variance pulses matched an automated rogue radio exfiltration signature.",
    };
  }

  if (threat === "COMMUNICATION_JAMMING") {
    return {
      threat_type: "COMMUNICATION_JAMMING",
      compromised_vector: "Wireless Ingress / Antenna Front-End",
      risk_level: "HIGH",
      risk_justification:
        "Wideband denial-of-service attack attempting to force transaction fallback to unencrypted offline store-and-forward mode.",
      pci_containment_action:
        "Block offline fallback transactions, enforce cloud handshake validation, and flag for physical inspection.",
      action: "LOCK_TERMINAL",
      confidence: 0.89,
      threat_diagnosis: [
        "High-density packet flood across receiver front-end",
        "Carrier lock suppressed via RF front-end wideband saturation",
        "Attempted bypass of online acquirer cryptographic verification",
      ],
      rationale:
        "Rapid packet saturation detected aimed at forcing unencrypted payment fallback.",
    };
  }

  return {
    threat_type: "FALSE_POSITIVE",
    compromised_vector: "External Ambient Environment",
    risk_level: "LOW",
    risk_justification: "Transient RF anomaly within acceptable environmental tolerance.",
    pci_containment_action:
      "No remediation required. Maintain standard operational state.",
    action: "IGNORE",
    confidence: 0.95,
    threat_diagnosis: [
      "High power variance consistent with passing mobile phone[cite: 8]",
      "Non-periodic, transient RF spike",
      "No sustained parasite coupling on internal traces",
    ],
    rationale: "Transient spatial fluctuation caused by environmental noise.",
  };
}

// ---------------------------------------------------------------------------
// Akamai Cloud Inference Integration
// ---------------------------------------------------------------------------

async function evaluateWithAgent(metrics: WindowMetrics): Promise<AgentVerdict> {
  const isAttenuationBreach = metrics.meanRssi < -82.0;

  const systemPrompt = `You are an automated PCI PTS (PIN Transaction Security) v6.0 and PCI DSS v4.0 Hardware Forensics Engine integrated into Akamai Cloud.
You analyze physical-layer RF side-channel anomalies captured by Software-Defined Radios monitoring EMV Point-of-Sale terminals.

Your output MUST be strictly deterministic, highly technical, and adhere strictly to PCI PTS Module 1 and PCI DSS Req 9.9 standards.
Do NOT provide generic conversational filler.

Respond in strict JSON matching this structure:
{
  "threat_type": "SNIFFING_TAP" | "DATA_EXFIL_BEACON" | "COMMUNICATION_JAMMING" | "FALSE_POSITIVE",
  "confidence": 0.0 - 1.0,
  "compromised_vector": "ISO/IEC 7816-3 Smart Card Interface" | "Physical Chassis Perimeter / Ambient Mesh Sensor" | "SPI/UART Data Bus",
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "risk_justification": "1-sentence justification citing CVSS or PCI DSS 9.9 impact",
  "pci_containment_action": "Immediate automated remediation referencing TR-31/DUKPT key zeroization, transaction token revocation, or terminal quarantine",
  "action": "LOCK_TERMINAL" | "ISOLATE_OFFLINE" | "FLAG_FOR_INSPECTION" | "IGNORE",
  "threat_diagnosis": [
    "Root-cause RF mechanism identified",
    "Target subsystem affected",
    "Physical attacker proximity or hardware signature"
  ],
  "rationale": "Direct 1-2 sentence technical summary of the physical RF anomaly."
}`;

  const userContext = `TELEMETRY EVENT CONTEXT:
- Terminal Identifier: ${metrics.deviceId}
- Detection Method: Physical-Layer RF Spectral Analysis (RTL-SDR R820T2)
- 8-Point FFT Spectral Profile (dBm): [${metrics.spectral.bins.join(", ")}]
- Observed Wideband Power: ${metrics.meanRssi} dBm (Peak: ${metrics.maxRssi} dBm, Variance: ${metrics.variance} dBm²)
- Anomaly Vector: ${
    isAttenuationBreach
      ? `LOWER BOUND BREACH (P_RF < P_min of -82.0 dBm). Signal dropped to ${metrics.meanRssi} dBm. Indicates physical RF shielding (Faraday enclosure) or severed antenna trace attempting to blind tamper detection.`
      : `UPPER BOUND BREACH (P_RF > P_max of -38.0 dBm). Delta: +${metrics.deltaDb} dB / ~${metrics.powerSurgeRatio}x power surge on 48.78 MHz harmonic.`
  }
- Sensor State: ISO/IEC 7816 bus active during card insertion
- Window Duration: ${metrics.durationSec}s (${metrics.sampleCount} samples)
- Preliminary Heuristic: ${metrics.likelyType}`;

  const targetUrl =
    process.env.AGENT_ENDPOINT_URL || "https://api.linode.com/v4/ai/inference";
  const apiKey = process.env.AGENT_API_KEY || process.env.AKAMAI_AI_TOKEN || "";
  const modelId = process.env.AGENT_MODEL || "meta/llama-3-8b-instruct";

  try {
    const res = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: modelId,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userContext },
        ],
        temperature: 0.1,
        max_tokens: 350,
        response_format: { type: "json_object" },
      }),
    });

    if (res.ok) {
      const data = await res.json();
      const rawText: string = data.choices?.[0]?.message?.content ?? data.response;
      const parsed = JSON.parse(rawText) as AgentVerdict;

      return {
        ...parsed,
        confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0.95,
        rationale:
          parsed.rationale ||
          (Array.isArray(parsed.threat_diagnosis)
            ? parsed.threat_diagnosis.join(". ")
            : "Deterministic RF anomaly confirmed by physical bounds."),
      };
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.warn(`[!] Akamai Cloud AI unreachable (${message}). Using PCI fallback...`);
  }

  return createFallbackVerdict(
    metrics.likelyType,
    metrics.deltaDb,
    metrics.powerSurgeRatio,
    metrics.spectral
  );
}

// ---------------------------------------------------------------------------
// Server Initialization & Bun Engine Setup
// ---------------------------------------------------------------------------

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev });
const handle = app.getRequestHandler();
const PORT = parseInt(process.env.PORT || "3000", 10);

await app.prepare();

Bun.serve<WSData>({
  port: PORT,

  // 1. HTTP Router & WebSocket Upgrader
  async fetch(req, server) {
    const url = new URL(req.url);

    // Hardware Ingestion Socket (/ingest)[cite: 7]
    if (url.pathname === "/ingest") {
      const upgraded = server.upgrade(req, {
        data: { type: "INGEST", connectedAt: Date.now() },
      });
      if (upgraded) return undefined;
      return new Response("WebSocket Upgrade Failed (/ingest)", { status: 400 });
    }

    // Dashboard Telemetry Egress Socket (/egress)[cite: 4, 5]
    if (url.pathname === "/egress") {
      const upgraded = server.upgrade(req, {
        data: { type: "EGRESS", connectedAt: Date.now() },
      });
      if (upgraded) return undefined;
      return new Response("WebSocket Upgrade Failed (/egress)", { status: 400 });
    }

    // Bridge standard HTTP requests into Next.js App Router
    return new Promise<Response>(async (resolve) => {
      const chunks: Buffer[] = [];
      let statusCode = 200;
      let statusText = "OK";
      const headers = new Headers();

      const nodeReq = Object.assign(
        Readable.from(req.body ? Buffer.from(await req.arrayBuffer()) : []),
        {
          url: url.pathname + url.search,
          method: req.method,
          headers: Object.fromEntries(req.headers.entries()),
          rawHeaders: Array.from(req.headers.entries()).flat(),
          socket: { encrypted: url.protocol === "https:" },
        }
      );

      const nodeRes = Object.assign(
        new Writable({
          write(chunk, _encoding, callback) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            callback();
          },
          final(callback) {
            const body = Buffer.concat(chunks);
            resolve(new Response(body, { status: statusCode, statusText, headers }));
            callback();
          },
        }),
        {
          statusCode: 200,
          statusMessage: "OK",
          headersSent: false,
          setHeader(name: string, value: string | string[]) {
            if (Array.isArray(value)) {
              headers.delete(name);
              value.forEach((v) => headers.append(name, v));
            } else {
              headers.set(name, value);
            }
          },
          getHeader(name: string) {
            return headers.get(name);
          },
          hasHeader(name: string) {
            return headers.has(name);
          },
          removeHeader(name: string) {
            headers.delete(name);
          },
          writeHead(code: number, messageOrHeaders?: any, maybeHeaders?: any) {
            statusCode = code;
            if (typeof messageOrHeaders === "string") {
              statusText = messageOrHeaders;
            }
            const h =
              typeof messageOrHeaders === "object" ? messageOrHeaders : maybeHeaders;
            if (h) {
              for (const [k, v] of Object.entries(h)) {
                this.setHeader(k, v as any);
              }
            }
            return this;
          },
          end(chunk?: any) {
            if (chunk) {
              chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            }
            const body = Buffer.concat(chunks);
            resolve(new Response(body, { status: statusCode, statusText, headers }));
          },
        }
      );

      try {
        await handle(nodeReq as any, nodeRes as any);
      } catch (err: unknown) {
        console.error("[Next.js Render Error]:", err);
        resolve(new Response("Internal Server Error", { status: 500 }));
      }
    });
  },

  // 2. High-Throughput uWebSockets Engine
  websocket: {
    open(ws: ServerWebSocket<WSData>) {
      if (ws.data.type === "EGRESS") {
        ws.subscribe("dashboard-feed");
      }
    },

    // server.ts (websocket.message snippet)
async message(ws: ServerWebSocket<WSData>, message: string | Buffer) {
  if (ws.data.type !== "INGEST") return;

  try {
    const raw: RawHardwarePayload = JSON.parse(message.toString());
    const payload = parseHardwarePayload(raw);

    if (!payload) {
      console.warn("[Ingest] Dropped invalid packet missing device_id, timestamp, or spectrum");
      return;
    }

    ws.data.deviceId = payload.device_id;

    // Stream normalized telemetry and 8-point FFT to dashboard egress
    ws.publish(
      "dashboard-feed",
      JSON.stringify({
        event: "TELEMETRY_POINT",
        device_id: payload.device_id,
        rssi: payload.rssi,
        fft: payload.fft,
        timestamp: payload.timestamp,
      })
    );

    // Run state-latched threshold and spectral analysis
    const result = tracker.processReading(payload);
    if (!result) return;

    if (result.kind === "RECOVERED") {
      console.log(`[STATUS RESTORED] Terminal: ${result.deviceId} recovered.`);
      const [recoveryRecord] = await db
        .insert(incidentVerdicts)
        .values({
          deviceId: result.deviceId,
          classification: "SECURE_RECOVERED",
          confidence: 1.0,
          meanRssi: payload.rssi,
          variance: 0.0,
          sampleCount: 0,
          rationale: "RF physical emissions stabilized at safe baseline for > 2.0s.",
          actionTaken: "RESTORE_NORMAL",
          rawSeries: JSON.stringify([]),
        })
        .returning();

      const recoveryPayload = JSON.stringify({
        event: "STATUS_RECOVERED",
        incidentId: recoveryRecord.id,
        deviceId: result.deviceId,
        status: "SECURE",
        timestamp: result.recoveryTimestamp,
      });

      ws.publish("dashboard-feed", recoveryPayload);
      ws.send(recoveryPayload);
      return;
    }

    // Branch 2: Threat Alert
    const metrics = result.metrics!;
    console.log(`\n[ALERT TRIGGERED] Terminal: ${metrics.deviceId} | RSSI: ${metrics.meanRssi} dBm`);
    console.log(`8-Point FFT: [${metrics.spectral.bins.join(", ")}] dBm`);

    const verdict = await evaluateWithAgent(metrics);

    console.log("\n---------------- AGENT FORENSIC REPORT ----------------");
    console.log(`Threat Classification:  ${verdict.threat_type}`);
    console.log(`Compromised Vector:     ${verdict.compromised_vector}`);
    console.log(
      `Risk Level:             ${verdict.risk_level} (${(verdict.confidence * 100).toFixed(1)}% Confidence)`
    );
    console.log(`PCI Containment Action: ${verdict.pci_containment_action}`);
    console.log(`Physical Relay Action:  ${verdict.action}`);
    console.log("=======================================================\n");

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

    const alertPayload = JSON.stringify({
      event: "INCIDENT_ALERT",
      incidentId: record.id,
      deviceId: metrics.deviceId,
      verdict,
    });

    ws.publish("dashboard-feed", alertPayload);
    ws.send(alertPayload);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    console.error("[Telemetry Ingest Error]:", msg);
  }
},

    close(ws: ServerWebSocket<WSData>) {
      if (ws.data.type === "EGRESS") {
        ws.unsubscribe("dashboard-feed");
      }
    },
  },
});

console.log(`> Bun runtime active on http://localhost:${PORT}`);
console.log(`> Telemetry Ingest: ws://localhost:${PORT}/ingest[cite: 7]`);
console.log(`> Dashboard Egress: ws://localhost:${PORT}/egress[cite: 4, 5]`);