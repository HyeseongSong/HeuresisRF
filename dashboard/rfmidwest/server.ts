// server.ts
import next from "next";
import type { ServerWebSocket } from "bun";
import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { db } from "./lib/db";
import { incidentVerdicts } from "./lib/schema";

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
  timestamp: number;
  fft: number[]; // 8-point downsampled FFT spectral power values in dBm
}

export interface RawHardwarePayload {
  device_id: string;
  timestamp: number;
  spectrum?: Record<string, number>;
  rssi?: number;
  fft?: number[];
}

export interface RSSIPoint {
  t: number;
  rssi: number;
}

export interface SpectralAnalysis {
  bins: number[];
  peakBinIndex: number;
  peakBinPower: number;
  spectralSpreadDb: number;
  isNarrowbandSpike: boolean;
}

export interface WindowMetrics {
  deviceId: string;
  sampleCount: number;
  meanRssi: number;
  variance: number;
  minRssi: number;
  maxRssi: number;
  isAttenuationBreach: boolean;
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
  forensic_analysis?: string;
  pci_compliance_impact?: string;
}

interface WSData {
  type: "INGEST" | "EGRESS";
  deviceId?: string;
  connectedAt: number;
}

interface BreachCandidate {
  type: "UPPER" | "LOWER";
  consecutiveCount: number;
  firstBreachTimestamp: number;
  peakBins: number[];
}

// ---------------------------------------------------------------------------
// Hardware Payload Adapter
// ---------------------------------------------------------------------------

export function parseHardwarePayload(raw: RawHardwarePayload): POSTelemetryPayload | null {
  if (!raw.device_id || typeof raw.timestamp !== "number") {
    return null;
  }

  // Backward compatibility with legacy simulate.ts mock payloads
  if (typeof raw.rssi === "number" && Array.isArray(raw.fft)) {
    return {
      device_id: raw.device_id,
      rssi: raw.rssi,
      timestamp: raw.timestamp,
      fft: raw.fft,
    };
  }

  if (!raw.spectrum || typeof raw.spectrum !== "object") {
    return null;
  }

  const entries = Object.entries(raw.spectrum);
  if (entries.length === 0) return null;

  entries.sort((a, b) => {
    const fA = parseFloat(a[0].replace("M", ""));
    const fB = parseFloat(b[0].replace("M", ""));
    return fA - fB;
  });

  const powers = entries.map(([, p]) => p);
  const N = powers.length;

  // 1. Calculate Mean Channel Power Spectral Density (Normalized RSSI in dBm)
  let sumLinearMilliwatts = 0;
  for (let i = 0; i < N; i++) {
    sumLinearMilliwatts += Math.pow(10, powers[i] / 10);
  }
  const meanPowerMw = sumLinearMilliwatts / N;
  const channelRssi = Number((10 * Math.log10(meanPowerMw)).toFixed(2));

  // 2. Downsample 201 bins into 8 macro-bins using Peak-Hold
  const NUM_BINS = 8;
  const fft8: number[] = [];
  const chunkSize = N / NUM_BINS;

  for (let i = 0; i < NUM_BINS; i++) {
    const startIdx = Math.floor(i * chunkSize);
    const endIdx = Math.floor((i + 1) * chunkSize);
    const slice = powers.slice(startIdx, endIdx);
    const peakPower = Math.max(...slice);
    fft8.push(Number(peakPower.toFixed(2)));
  }

  return {
    device_id: raw.device_id,
    rssi: channelRssi,
    timestamp: raw.timestamp,
    fft: fft8,
  };
}

// ---------------------------------------------------------------------------
// State-Latched Hardware Bounds & Spectral Analyzer Engine
// ---------------------------------------------------------------------------

class POSSignalTracker {
  private windows = new Map<string, RSSIPoint[]>();
  private terminalStates = new Map<string, "SECURE" | "COMPROMISED">();
  private recoveryTimestamps = new Map<string, number>();
  private breachCandidates = new Map<string, BreachCandidate>();

  private readonly WINDOW_SECONDS = 3.0;
  private readonly MIN_SAMPLES = 4;

  // Physical-layer bounds (dBm)
  private readonly P_MAX = -38.0; 
  private readonly P_MIN = -82.0; 
  private readonly RECOVERY_REQUIRED_SEC = 2.0;

  // Asymmetric persistence thresholds @ 10 Hz:
  // Upper bound (shimmer/tap): 3 frames (300 ms) -> Fast trip before ISO/IEC 7816 cryptogram finishes
  private readonly CONSECUTIVE_UPPER_BREACHES = 3;
  // Lower bound (Faraday/severed trace): 12 frames (1.2 s) -> Rejects passing metal carts and nulls
  private readonly CONSECUTIVE_LOWER_BREACHES = 12;

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

    // 1. Sliding ring buffer maintenance
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

    // 4. Dual-trigger bounds evaluation
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
    // TRANSIENT SPIKE / NULL FILTERING (While SECURE)
    // -------------------------------------------------------------
    if (!isBreached) {
      this.breachCandidates.delete(device_id);
      this.recoveryTimestamps.delete(device_id);
      return null;
    }

    const activeBreachType: "UPPER" | "LOWER" = isLowerBreach ? "LOWER" : "UPPER";
    const candidate = this.breachCandidates.get(device_id);

    if (!candidate || candidate.type !== activeBreachType) {
      this.breachCandidates.set(device_id, {
        type: activeBreachType,
        consecutiveCount: 1,
        firstBreachTimestamp: timestamp,
        peakBins: [spectral.peakBinIndex],
      });
      return null;
    }

    candidate.consecutiveCount += 1;
    candidate.peakBins.push(spectral.peakBinIndex);
    this.breachCandidates.set(device_id, candidate);

    const requiredFrames =
      activeBreachType === "LOWER"
        ? this.CONSECUTIVE_LOWER_BREACHES
        : this.CONSECUTIVE_UPPER_BREACHES;

    if (candidate.consecutiveCount < requiredFrames) {
      return null;
    }

    if (isNarrowbandUpperBreach) {
      const recentBins = candidate.peakBins.slice(-this.CONSECUTIVE_UPPER_BREACHES);
      const isCarrierStable = recentBins.every((bin) => bin === recentBins[0]);
      if (!isCarrierStable) {
        this.breachCandidates.delete(device_id);
        return null;
      }
    }

    // -------------------------------------------------------------
    // SUSTAINED ATTACK CONFIRMED: TRANSITION SECURE -> COMPROMISED
    // -------------------------------------------------------------
    this.terminalStates.set(device_id, "COMPROMISED");
    this.breachCandidates.delete(device_id);
    this.recoveryTimestamps.delete(device_id);

    // Extract metrics from the active breach window
    const activeSliceCount = activeBreachType === "LOWER" ? this.CONSECUTIVE_LOWER_BREACHES : 3;
    const activeSlice = series.slice(-activeSliceCount);
    const activeRssiVals = activeSlice.map((s) => s.rssi);
    const activeMeanRssi = activeRssiVals.reduce((a, b) => a + b, 0) / activeRssiVals.length;
    const activeVariance =
      activeRssiVals.reduce((acc, val) => acc + Math.pow(val - activeMeanRssi, 2), 0) /
      activeRssiVals.length;

    const allRssiVals = series.map((s) => s.rssi);
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
    const effectivePowerDbm = Math.max(activeMeanRssi, spectral.peakBinPower);
    const deltaDb = Number((effectivePowerDbm - this.P_MAX).toFixed(2));
    const powerSurgeRatio =
      deltaDb > 0 ? Number(Math.pow(10, deltaDb / 10).toFixed(1)) : 1.0;

    let likelyType: ThreatType = "FALSE_POSITIVE";
    if (isLowerBreach) {
      likelyType = "COMMUNICATION_JAMMING";
    } else if (activeVariance > 14.0 && !spectral.isNarrowbandSpike) {
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
        meanRssi: Number(activeMeanRssi.toFixed(2)),
        variance: Number(activeVariance.toFixed(2)),
        minRssi: Math.min(...allRssiVals),
        maxRssi: Math.max(...allRssiVals),
        isAttenuationBreach: isLowerBreach,
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
  spectral?: SpectralAnalysis,
  isAttenuationBreach?: boolean
): AgentVerdict {
  if (isAttenuationBreach) {
    return {
      threat_type: "COMMUNICATION_JAMMING",
      compromised_vector: "Physical Chassis Perimeter / Ambient Mesh Sensor",
      risk_level: "HIGH",
      risk_justification:
        "Severe physical RF suppression detected (< -82.0 dBm); indicates Faraday shielding or severed antenna trace violating PCI DSS v4.0 Req 9.9 tamper monitoring.",
      pci_containment_action:
        "Isolate terminal from network routing, invalidate cryptographic session keys, and dispatch security technician for chassis inspection.",
      action: "ISOLATE_OFFLINE",
      confidence: 0.94,
      threat_diagnosis: [
        "Sustained RF attenuation collapse below -82.0 dBm baseline bound",
        "Probable conductive foil wrapping or enclosure tamper",
        "Receiver front-end blinding to suppress physical tamper telemetry",
      ],
      rationale:
        "Physical RF attenuation collapsed below -82.0 dBm threshold, indicating conductive shielding or antenna severance.",
    };
  }

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
        "Parasitic transmitter coupling detected on smart card I/O bus lines",
        "EMV chip slot physical trace tapped via invasive shimmer overlay",
        `Observed +${deltaDb} dB surge (~${powerSurge}x baseline power) concentrated on ${peakBinStr}`,
      ],
      rationale: `Upper RF bound breach detected (+${deltaDb} dB / ~${powerSurge}x power surge). Parasitic transmitter coupling on smart card I/O bus lines.`,
    };
  }

  if (threat === "DATA_EXFIL_BEACON") {
    return {
      threat_type: "DATA_EXFIL_BEACON",
      compromised_vector: "433 MHz / 2.4 GHz Secondary Transmitter Trace",
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
      "High power variance consistent with passing mobile phone",
      "Non-periodic, transient RF spike",
      "No sustained parasite coupling on internal traces",
    ],
    rationale: "Transient spatial fluctuation caused by environmental noise.",
  };
}

// ---------------------------------------------------------------------------
// Forensic Response Sanitizer & Repair Pipeline
// ---------------------------------------------------------------------------

function safeParseAgentResponse(rawText: string): AgentVerdict | null {
  if (!rawText || typeof rawText !== "string") return null;

  // 1. Strip markdown fences if present
  let cleaned = rawText.trim();
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  }

  // 2. Direct JSON attempt
  try {
    return JSON.parse(cleaned) as AgentVerdict;
  } catch {
    // Continue to repair attempts
  }

  // 3. Attempt repairing unescaped newlines within JSON string values
  try {
    const sanitized = cleaned.replace(/[\r\n]+/g, " ");
    return JSON.parse(sanitized) as AgentVerdict;
  } catch {
    // Continue to truncated repair
  }

  // 4. Repair truncated JSON (Unterminated string / unclosed brackets)
  try {
    let repair = cleaned.trim();

    // Check if cut off inside a string (odd number of unescaped quotes)
    const quoteMatches = repair.match(/(?<!\\)"/g) || [];
    if (quoteMatches.length % 2 !== 0) {
      repair += '"';
    }

    // Balance unclosed brackets and braces
    const openBraces = (repair.match(/{/g) || []).length;
    const closeBraces = (repair.match(/}/g) || []).length;
    for (let i = 0; i < openBraces - closeBraces; i++) {
      repair += "}";
    }

    const openBrackets = (repair.match(/\[/g) || []).length;
    const closeBrackets = (repair.match(/]/g) || []).length;
    for (let i = 0; i < openBrackets - closeBrackets; i++) {
      repair += "]";
    }

    const repairedObj = JSON.parse(repair);
    if (repairedObj && typeof repairedObj === "object" && repairedObj.threat_type) {
      return repairedObj as AgentVerdict;
    }
  } catch {
    console.warn("[Agent] JSON auto-repair failed. Raw snippet:", cleaned.slice(-120));
  }

  return null;
}

// ---------------------------------------------------------------------------
// Akamai Cloud Inference Integration
// ---------------------------------------------------------------------------

async function evaluateWithAgent(metrics: WindowMetrics): Promise<AgentVerdict> {
  const isAttenuationBreach = metrics.isAttenuationBreach;

  const systemPrompt = `You are an elite PCI Security Specialist, Embedded Hardware Forensics Expert, and automated RF Physical-Layer Diagnostics Engine hosted on Akamai Cloud.
You analyze Software-Defined Radio (SDR) side-channel RF emissions captured from EMV Point-of-Sale (POS) terminals to detect physical tampering, parasitic shimmers, rogue taps, Faraday shielding, and wireless jamming.

Your objective is to provide a rigorous, highly technical forensic assessment grounded in ISO/IEC 7816-3 protocols, analog RF side-channel physics, PCI PTS v6.0 Module 1, and PCI DSS v4.0 Requirement 9.9.

Provide thorough, technically descriptive explanations of the root cause, coupling mechanisms, and hardware attack surface. Keep string values formatted on a single continuous line without unescaped literal newlines.

CRITICAL OUTPUT CONSTRAINTS:
- Output MUST be valid, raw RFC 8259 JSON starting with '{' and ending with '}'.
- Do NOT wrap output in markdown code blocks (NO \`\`\` or \`\`\`json fences).
- Do NOT include any introductory or conversational text.

Respond ONLY with valid JSON matching this exact schema:
{
  "threat_type": "SNIFFING_TAP" | "DATA_EXFIL_BEACON" | "COMMUNICATION_JAMMING" | "FALSE_POSITIVE",
  "confidence": 0.0 - 1.0,
  "compromised_vector": "ISO/IEC 7816-3 Smart Card Interface" | "Physical Chassis Perimeter / Ambient Mesh Sensor" | "SPI/UART Data Bus" | "External Ambient Environment",
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "risk_justification": "Detailed justification evaluating CVSS impact, plaintext credential exposure (Track-2 equivalent data, offline PIN), and breach of PCI physical tamper boundaries.",
  "pci_containment_action": "Comprehensive containment directives specifying immediate hardware and acquirer actions (e.g., TR-31 / DUKPT Future Key zeroization, transaction cryptogram ARQC invalidation, gateway token quarantine, or physical terminal decommission).",
  "action": "LOCK_TERMINAL" | "ISOLATE_OFFLINE" | "FLAG_FOR_INSPECTION" | "IGNORE",
  "threat_diagnosis": [
    "Root-cause physical/RF anomaly mechanism (carrier frequency, harmonic power, capacitive/inductive coupling)",
    "Targeted cryptographic, bus, or transaction subsystem affected",
    "Physical attacker proximity, implant footprint, or rogue hardware signature"
  ],
  "forensic_analysis": "Comprehensive technical breakdown of the physical side-channel emission. Explain how the observed spectral spread, harmonic surge, and signal persistence map to the hardware exploit, whether capacitive contact sniffing, rogue wireless offloading, or Faraday attenuation.",
  "pci_compliance_impact": "Direct analysis of non-compliance under PCI PTS v6.0 (Section B1/B2) and PCI DSS v4.0 (Req 9.9 tamper detection obligations).",
  "rationale": "Concise executive forensic summary combining the physical observation with the primary threat conclusion."
}`;

  const userContext = `HARDWARE TELEMETRY EVENT CONTEXT:
- Terminal Identifier: ${metrics.deviceId}
- Detection Sensor: RTL-SDR Physical-Layer RF Monitor (R820T2)
- 8-Point Downsampled FFT Spectrum (dBm): [${metrics.spectral.bins.join(", ")}]
- Dominant Harmonic: Bin ${metrics.spectral.peakBinIndex} @ ${metrics.spectral.peakBinPower} dBm (+${metrics.spectral.spectralSpreadDb} dB spectral spread over noise floor)
- Narrowband Spike Status: ${metrics.spectral.isNarrowbandSpike ? "CONFIRMED (>= 18.0 dB isolation)" : "NEGATIVE (Wideband or diffuse)"}
- Active Channel Power (RSSI): ${metrics.meanRssi} dBm (Active Variance: ${metrics.variance} dBm²)
- Anomaly Classification Vector: ${
    isAttenuationBreach
      ? `LOWER ATTENUATION BREACH (P_RF < P_min of -82.0 dBm). Signal collapsed to ${metrics.meanRssi} dBm across all bins. Indicates physical Faraday enclosure, copper tape foil wrap, or severed chassis antenna trace attempting to blind physical tamper monitoring.`
      : `UPPER HARMONIC BREACH (P_RF > P_max of -38.0 dBm). Effective Surge: +${metrics.deltaDb} dB (~${metrics.powerSurgeRatio}x power multiplier relative to P_max threshold).`
  }
- Target Bus Active: ISO/IEC 7816-3 contact lines (EMV Smart Card Slot)
- Sustained Window Duration: ${metrics.durationSec}s (${metrics.sampleCount} total samples)
- Heuristic Pre-Classifier: ${metrics.likelyType}`;

  const targetUrl =
    process.env.AGENT_ENDPOINT_URL || "[https://api.linode.com/v4/ai/inference](https://api.linode.com/v4/ai/inference)";
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
        temperature: 0.15,
        max_tokens: 1800,
        response_format: { type: "json_object" },
      }),
    });

    if (res.ok) {
      const data = await res.json();
      const rawText: string = data.choices?.[0]?.message?.content ?? data.response;
      const parsed = safeParseAgentResponse(rawText);

      if (parsed) {
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
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.warn(`[!] Akamai Cloud AI unreachable (${message}). Using PCI fallback...`);
  }

  return createFallbackVerdict(
    metrics.likelyType,
    metrics.deltaDb,
    metrics.powerSurgeRatio,
    metrics.spectral,
    isAttenuationBreach
  );
}

// ---------------------------------------------------------------------------
// Server Initialization & Bun Engine Setup
// ---------------------------------------------------------------------------

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev });
const handle = app.getRequestHandler();
const PORT = parseInt(process.env.PORT || "3000", 10);
const ADMIN_API_KEY = process.env.RF_SENTINEL_ADMIN_KEY || "adm_rf_secret_dev";

await app.prepare();

Bun.serve<WSData>({
  port: PORT,
  hostname: "0.0.0.0",

  async fetch(req, server) {
    const url = new URL(req.url);

    // Administrative Lockout Override Endpoint
    if (url.pathname === "/api/terminal/reset" && req.method === "POST") {
      const authHeader = req.headers.get("authorization");
      if (!authHeader || authHeader !== `Bearer ${ADMIN_API_KEY}`) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      let body: { deviceId?: string };
      try {
        body = await req.json();
      } catch {
        return new Response(JSON.stringify({ error: "Malformed JSON payload" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }

      const { deviceId } = body;
      if (!deviceId) {
        return new Response(JSON.stringify({ error: "Missing required field: deviceId" }), {
          status: 422,
          headers: { "Content-Type": "application/json" },
        });
      }

      tracker.manualReset(deviceId);

      const [record] = await db
        .insert(incidentVerdicts)
        .values({
          deviceId,
          classification: "ADMINISTRATIVE_OVERRIDE",
          confidence: 1.0,
          meanRssi: -60.0,
          variance: 0.0,
          sampleCount: 0,
          rationale: "Terminal locked state cleared via manual administrative override endpoint.",
          actionTaken: "MANUAL_UNLOCK",
          rawSeries: JSON.stringify({ overrideBy: "ADMIN_CONSOLE", timestamp: Date.now() / 1000 }),
        })
        .returning();

      const resetPayload = JSON.stringify({
        event: "STATUS_RECOVERED",
        incidentId: record.id,
        deviceId,
        status: "SECURE",
        timestamp: Date.now() / 1000,
      });

      server.publish("dashboard-feed", resetPayload);

      return new Response(
        JSON.stringify({ status: "OK", incidentId: record.id, timestamp: Date.now() / 1000 }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    // Hardware Ingestion Socket (/ingest)
    if (url.pathname === "/ingest") {
      const upgraded = server.upgrade(req, {
        data: { type: "INGEST", connectedAt: Date.now() },
      });
      if (upgraded) return undefined;
      return new Response("WebSocket Upgrade Failed (/ingest)", { status: 400 });
    }

    // Dashboard Telemetry Egress Socket (/egress)
    if (url.pathname === "/egress") {
      const upgraded = server.upgrade(req, {
        data: { type: "EGRESS", connectedAt: Date.now() },
      });
      if (upgraded) return undefined;
      return new Response("WebSocket Upgrade Failed (/egress)", { status: 400 });
    }

    // Bridge HTTP requests into Next.js using Node.js IncomingMessage & ServerResponse
    return new Promise<Response>(async (resolve) => {
      const socket = new Socket();
      const nodeReq = new IncomingMessage(socket);
      nodeReq.url = url.pathname + url.search;
      nodeReq.method = req.method;

      req.headers.forEach((val, key) => {
        nodeReq.headers[key.toLowerCase()] = val;
      });

      const bodyBuffer = req.body ? Buffer.from(await req.arrayBuffer()) : null;
      if (bodyBuffer) {
        nodeReq.push(bodyBuffer);
      }
      nodeReq.push(null);

      const nodeRes = new ServerResponse(nodeReq);
      const chunks: Buffer[] = [];

      nodeRes.write = function (chunk: any) {
        if (chunk) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        return true;
      };

      nodeRes.end = function (chunk: any) {
        if (chunk) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }

        const resBody = Buffer.concat(chunks);
        const headers = new Headers();
        const rawHeaders = nodeRes.getHeaders();

        for (const [key, val] of Object.entries(rawHeaders)) {
          if (val === undefined || val === null) continue;
          if (Array.isArray(val)) {
            val.forEach((v) => headers.append(key, String(v)));
          } else {
            headers.set(key, String(val));
          }
        }

        resolve(
          new Response(resBody, {
            status: nodeRes.statusCode || 200,
            statusText: nodeRes.statusMessage || "OK",
            headers,
          })
        );
        return nodeRes;
      };

      try {
        await handle(nodeReq, nodeRes);
      } catch (err: unknown) {
        console.error("[Next.js Render Error]:", err);
        resolve(new Response("Internal Server Error", { status: 500 }));
      }
    });
  },

  websocket: {
    open(ws: ServerWebSocket<WSData>) {
      if (ws.data.type === "EGRESS") {
        ws.subscribe("dashboard-feed");
        console.log("[WebSocket] Egress connection established.");
      } else if (ws.data.type === "INGEST") {
        console.log("[WebSocket] Ingest connection established.");
      }
    },

    async message(ws: ServerWebSocket<WSData>, message: string | Buffer) {
      if (ws.data.type !== "INGEST") return;

      try {
        const raw: RawHardwarePayload = JSON.parse(message.toString());
        const payload = parseHardwarePayload(raw);

        if (!payload) {
          return;
        }
        console.log(`[Hardware Data] Received: ${JSON.stringify(payload)}`);

        ws.data.deviceId = payload.device_id;

        // Broadcast standardized telemetry point to dashboard egress
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

        const result = tracker.processReading(payload);
        if (!result) return;

        // -------------------------------------------------------------
        // BRANCH 1: RECOVERY DETECTED -> PERSIST TO DB
        // -------------------------------------------------------------
        if (result.kind === "RECOVERED") {
          console.log("\n=======================================================");
          console.log(`[STATUS RESTORED] Terminal: ${result.deviceId}`);
          console.log(`Signal stabilized within safe baseline for > 2.0s.`);
          console.log(`Writing RECOVERY record to PostgreSQL...`);
          console.log("=======================================================\n");

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

        // -------------------------------------------------------------
        // BRANCH 2: THREAT ALERT -> EVALUATE & PERSIST TO DB
        // -------------------------------------------------------------
        const metrics = result.metrics;

        console.log("\n=======================================================");
        console.log(`[ALERT TRIGGERED] Terminal: ${metrics.deviceId}`);
        console.log(
          `Window: ${metrics.sampleCount} samples | Mean: ${metrics.meanRssi} dBm | Variance: ${metrics.variance} dBm²`
        );
        console.log(`8-Point FFT: [${metrics.spectral.bins.join(", ")}] dBm`);
        console.log(
          `Dominant Harmonic: Bin ${metrics.spectral.peakBinIndex} @ ${metrics.spectral.peakBinPower} dBm (+${metrics.spectral.spectralSpreadDb} dB spread)`
        );
        console.log(
          `RF Harmonic Surge: +${metrics.deltaDb} dB (~${metrics.powerSurgeRatio}x power)`
        );
        console.log(`Pre-Heuristic: ${metrics.likelyType}`);
        console.log("Invoking Akamai Hosted AI Forensics Engine...");

        const verdict = await evaluateWithAgent(metrics);

        console.log("\n---------------- AGENT FORENSIC REPORT ----------------");
        console.log(`Threat Classification:  ${verdict.threat_type}`);
        console.log(`Compromised Vector:     ${verdict.compromised_vector}`);
        console.log(
          `Risk Level:             ${verdict.risk_level} (${(verdict.confidence * 100).toFixed(1)}% Confidence)`
        );
        console.log(`PCI Containment Action: ${verdict.pci_containment_action}`);
        console.log(`Physical Relay Action:  ${verdict.action}`);
        if (verdict.threat_diagnosis?.length) {
          console.log("\nThreat Diagnosis:");
          verdict.threat_diagnosis.forEach((point, idx) => {
            console.log(`  ${idx + 1}. ${point}`);
          });
        }
        if (verdict.forensic_analysis) {
          console.log(`\nForensic Analysis:\n${verdict.forensic_analysis}`);
        }
        if (verdict.pci_compliance_impact) {
          console.log(`\nPCI Compliance Impact:\n${verdict.pci_compliance_impact}`);
        }
        console.log(`\nTechnical Rationale:    ${verdict.rationale}`);
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

console.log(`> Bun runtime active on [http://0.0.0.0](http://0.0.0.0):${PORT}`);
console.log(`> Telemetry Ingest: ws://0.0.0.0:${PORT}/ingest`);
console.log(`> Dashboard Egress: ws://0.0.0.0:${PORT}/egress`);