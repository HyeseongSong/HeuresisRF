import type { AgentVerdict, SpectralAnalysis, ThreatType, WindowMetrics } from "./types";

const SYSTEM_PROMPT = `You are an elite PCI Security Specialist, Embedded Hardware Forensics Expert, and automated RF Physical-Layer Diagnostics Engine hosted on Akamai Cloud.
You analyze Software-Defined Radio (SDR) side-channel RF emissions captured from EMV Point-of-Sale (POS) terminals to detect physical tampering, parasitic shimmers, rogue taps, Faraday shielding, and wireless jamming.

Your objective is to provide a rigorous, highly technical forensic assessment grounded in ISO/IEC 7816-3 protocols, analog RF side-channel physics, PCI PTS v6.0 Module 1, and PCI DSS v4.0 Requirement 9.9.

Provide thorough, technically descriptive explanations of the root cause, coupling mechanisms, and hardware attack surface. Keep string values formatted on a single continuous line without unescaped literal newlines.

CRITICAL OUTPUT CONSTRAINTS:
- Output MUST be valid, raw RFC 8259 JSON starting with '{' and ending with '}'.
- Do NOT wrap output in markdown code blocks.
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
    "Root-cause physical/RF anomaly mechanism",
    "Targeted cryptographic, bus, or transaction subsystem affected",
    "Physical attacker proximity, implant footprint, or rogue hardware signature"
  ],
  "forensic_analysis": "Comprehensive technical breakdown of physical side-channel emission.",
  "pci_compliance_impact": "Direct analysis of non-compliance under PCI PTS v6.0 and PCI DSS v4.0.",
  "rationale": "Concise executive forensic summary."
}`;

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
      // FIX 3B: Aligned with schema enum
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
      // FIX 3A: Added missing required schema fields
      forensic_analysis:
        "Chassis-level RF suppression observed across front-end receiver boundaries, indicating structural attenuation.",
      pci_compliance_impact:
        "Direct violation of PCI DSS v4.0 Requirement 9.9 tamper detection mechanisms.",
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
      // FIX 3B: Aligned with schema enum
      compromised_vector: "ISO/IEC 7816-3 Smart Card Interface",
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
        `Observed +${deltaDb} dB surge (~${powerSurge}x baseline power) concentrated on${peakBinStr}`,
      ],
      // FIX 3A: Added missing required schema fields
      forensic_analysis:
        "Parasitic inductive/capacitive coupling identified on smart card contact line radiating 48.78 MHz harmonics.",
      pci_compliance_impact:
        "Breach of PCI PTS v6.0 Module 1 physical attack surface requirements.",
      rationale: `Upper RF bound breach detected (+${deltaDb} dB / ~${powerSurge}x power surge). Parasitic transmitter coupling on smart card I/O bus lines.`,
    };
  }

  if (threat === "DATA_EXFIL_BEACON") {
    return {
      threat_type: "DATA_EXFIL_BEACON",
      // FIX 3B: Aligned with schema enum
      compromised_vector: "SPI/UART Data Bus",
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
      // FIX 3A: Added missing required schema fields
      forensic_analysis:
        "Periodic burst transmission trace detected consistent with secondary microcontroller hardware exfiltration.",
      pci_compliance_impact:
        "Non-compliant under PCI DSS v4.0 Requirement 9.9 regarding unauthorized transmission devices.",
      rationale:
        "Low-interval variance pulses matched an automated rogue radio exfiltration signature.",
    };
  }

  if (threat === "COMMUNICATION_JAMMING") {
    return {
      threat_type: "COMMUNICATION_JAMMING",
      // FIX 3B: Aligned with schema enum
      compromised_vector: "Physical Chassis Perimeter / Ambient Mesh Sensor",
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
      // FIX 3A: Added missing required schema fields
      forensic_analysis:
        "Wideband front-end energy saturation preventing authorized baseband transceiver synchronization.",
      pci_compliance_impact:
        "Breach of PCI PTS offline fallback containment protocols.",
      rationale:
        "Rapid packet saturation detected aimed at forcing unencrypted payment fallback.",
    };
  }

  return {
    threat_type: "FALSE_POSITIVE",
    compromised_vector: "External Ambient Environment",
    risk_level: "LOW",
    risk_justification: "Transient RF anomaly within acceptable environmental tolerance.",
    pci_containment_action: "No remediation required. Maintain standard operational state.",
    action: "IGNORE",
    confidence: 0.95,
    threat_diagnosis: [
      "High power variance consistent with passing mobile phone",
      "Non-periodic, transient RF spike",
      "No sustained parasite coupling on internal traces",
    ],
    // FIX 3A: Added missing required schema fields
    forensic_analysis: "Ambient RF energy envelope remained below critical hardware thresholds.",
    pci_compliance_impact: "Compliant. No physical boundaries compromised.",
    rationale: "Transient spatial fluctuation caused by environmental noise.",
  };
}

// FIX 3C: Type guard to validate payload structure before casting
function isValidVerdict(obj: unknown): obj is AgentVerdict {
  if (!obj || typeof obj !== "object") return false;
  const v = obj as Record<string, unknown>;
  return (
    typeof v.threat_type === "string" &&
    typeof v.action === "string" &&
    typeof v.risk_level === "string" &&
    typeof v.compromised_vector === "string"
  );
}

function safeParseAgentResponse(rawText: string): AgentVerdict | null {
  if (!rawText || typeof rawText !== "string") return null;

  // FIX 2A: Robust boundary slice - isolates JSON regardless of conversational markdown/prose
  const start = rawText.indexOf("{");
  const end = rawText.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;

  const candidate = rawText.slice(start, end + 1).trim();

  // Attempt 1: Direct parse
  try {
    const parsed: unknown = JSON.parse(candidate);
    if (isValidVerdict(parsed)) return parsed;
  } catch {}

  // Attempt 2: Sanitize unescaped newlines inside string literals
  try {
    const sanitized = candidate.replace(/(?<!\\)[\r\n]+/g, " ");
    const parsed: unknown = JSON.parse(sanitized);
    if (isValidVerdict(parsed)) return parsed;
  } catch {}

  // Attempt 3: Truncated JSON repair
  try {
    let repair = candidate;
    const quoteMatches = repair.match(/(?<!\\)"/g) || [];
    if (quoteMatches.length % 2 !== 0) repair += '"';

    // FIX 1B: LIFO stack closure (close nested arrays ']' BEFORE enclosing objects '}')
    const openBrackets = (repair.match(/\[/g) || []).length;
    const closeBrackets = (repair.match(/\]/g) || []).length;
    for (let i = 0; i < openBrackets - closeBrackets; i++) repair += "]";

    const openBraces = (repair.match(/\{/g) || []).length;
    const closeBraces = (repair.match(/\}/g) || []).length;
    for (let i = 0; i < openBraces - closeBraces; i++) repair += "}";

    const repairedObj: unknown = JSON.parse(repair);
    // FIX 3C: Replaced loose duck-typing with strict validation
    if (isValidVerdict(repairedObj)) {
      return repairedObj;
    }
  } catch {
    console.warn("[Agent] JSON auto-repair failed. Snippet:", candidate.slice(-80));
  }

  return null;
}

export async function evaluateWithAgent(metrics: WindowMetrics): Promise<AgentVerdict> {
  // FIX 2D: Safe navigation on optional `metrics.spectral` properties
  const spectralBins = metrics.spectral?.bins?.join(", ") ?? "N/A";
  const peakIndex = metrics.spectral?.peakBinIndex ?? 0;
  const peakPower = metrics.spectral?.peakBinPower ?? 0;
  const spread = metrics.spectral?.spectralSpreadDb ?? 0;
  const spikeStatus = metrics.spectral?.isNarrowbandSpike ? "CONFIRMED" : "NEGATIVE";

  // FIX 4B: Removed accidental newlines after labels in template literal
  const userContext = `HARDWARE TELEMETRY EVENT CONTEXT:
- Terminal Identifier: ${metrics.deviceId}
- Detection Sensor: RTL-SDR Physical-Layer RF Monitor (R820T2)
- 8-Point Downsampled FFT Spectrum (dBm): [${spectralBins}]
- Dominant Harmonic: Bin ${peakIndex} @ ${peakPower} dBm (+${spread} dB spread)
- Narrowband Spike Status: ${spikeStatus}
- Active Channel Power (RSSI): ${metrics.meanRssi} dBm (Active Variance:${metrics.variance} dBm²)
- Anomaly Classification Vector: ${
    metrics.isAttenuationBreach
      ? `LOWER ATTENUATION BREACH (< -82.0 dBm). Signal collapsed to ${metrics.meanRssi} dBm across all bins.`
      : `UPPER HARMONIC BREACH (> -38.0 dBm). Surge: +${metrics.deltaDb} dB (~${metrics.powerSurgeRatio}x power).`
  }
- Target Bus Active: ISO/IEC 7816-3 contact lines
- Sustained Window Duration: ${metrics.durationSec}s (${metrics.sampleCount} total samples)
- Heuristic Pre-Classifier: ${metrics.likelyType}`;

  // FIX 1A: Stripped Markdown link syntax from the fallback URL
  const targetUrl = process.env.AGENT_ENDPOINT_URL || "https://api.linode.com/v4/ai/inference";
  const apiKey = process.env.AGENT_API_KEY || process.env.AKAMAI_AI_TOKEN || "";
  const modelId = process.env.AGENT_MODEL || "meta/llama-3-8b-instruct";

  try {
    const res = await fetch(targetUrl, {
      method: "POST",
      // FIX 4A: 10-second timeout to prevent dangling connection leaks
      signal: AbortSignal.timeout(10000),
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: modelId,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: userContext },
        ],
        temperature: 0.15,
        max_tokens: 1800,
        response_format: { type: "json_object" },
      }),
    });

    // FIX 2C: Handle and log non-2xx HTTP responses explicitly
    if (!res.ok) {
      const errText = await res.text().catch(() => "Could not read response body");
      console.warn(`[!] Agent API returned HTTP ${res.status}:${errText}`);
    } else {
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
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.warn(`[!] Cloud AI unreachable (${message}). Using PCI fallback...`);
  }

  return createFallbackVerdict(
    metrics.likelyType,
    metrics.deltaDb,
    metrics.powerSurgeRatio,
    metrics.spectral,
    metrics.isAttenuationBreach
  );
}