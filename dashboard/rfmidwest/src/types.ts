export type ProcessResult =
  | { kind: "RECOVERED"; deviceId: string; recoveryTimestamp: number }
  | { kind: "ALERT"; deviceId: string; metrics: WindowMetrics };

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
  deviceId: string;
  rssi: number;
  timestamp: number;
  fft: number[];
}

export interface RawHardwarePayload {
  deviceId: string;
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

export interface WSData {
  type: "INGEST" | "EGRESS";
  deviceId?: string;
  connectedAt: number;
}
