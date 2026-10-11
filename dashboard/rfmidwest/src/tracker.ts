import type {
  POSTelemetryPayload,
  ProcessResult,
  RawHardwarePayload,
  RSSIPoint,
  SpectralAnalysis,
  ThreatType,
} from "./types";

function normalizeTimestamp(ts: number): number {
  return ts > 1e11 ? ts / 1000 : ts;
}

export function parseHardwarePayload(raw: RawHardwarePayload): POSTelemetryPayload | null {
  if (!raw.deviceId || typeof raw.timestamp !== "number") return null;

  const normalizedTimestamp = normalizeTimestamp(raw.timestamp);

  if (typeof raw.rssi === "number" && Array.isArray(raw.fft)) {
    return {
      deviceId: raw.deviceId,
      rssi: raw.rssi,
      timestamp: normalizedTimestamp,
      fft: raw.fft,
    };
  }

  if (!raw.spectrum || typeof raw.spectrum !== "object") return null;

  const rawEntries = Object.entries(raw.spectrum);
  if (rawEntries.length === 0) return null;

  const parsedEntries: { freq: number; power: number }[] = [];
  for (let i = 0; i < rawEntries.length; i++) {
    const [key, val] = rawEntries[i];
    if (typeof val === "number" && !Number.isNaN(val)) {
      const cleanFreq = parseFloat(key.replace(/[^0-9.]/g, ""));
      if (!Number.isNaN(cleanFreq)) {
        parsedEntries.push({ freq: cleanFreq, power: val });
      }
    }
  }

  if (parsedEntries.length === 0) return null;

  parsedEntries.sort((a, b) => a.freq - b.freq);

  const powers: number[] = new Array(parsedEntries.length);
  let sumLinearMilliwatts = 0;
  for (let i = 0; i < parsedEntries.length; i++) {
    const p = parsedEntries[i].power;
    powers[i] = p;
    sumLinearMilliwatts += Math.pow(10, p / 10);
  }

  const N = powers.length;
  const meanPowerMw = sumLinearMilliwatts / N;
  const channelRssi = Number((10 * Math.log10(meanPowerMw)).toFixed(2));

  const NUM_BINS = 8;
  const fft8: number[] = [];

  if (N >= NUM_BINS) {
    const chunkSize = N / NUM_BINS;
    for (let i = 0; i < NUM_BINS; i++) {
      const startIdx = Math.floor(i * chunkSize);
      const endIdx = i === NUM_BINS - 1 ? N : Math.floor((i + 1) * chunkSize);

      let maxBinVal = -Infinity;
      for (let j = startIdx; j < endIdx; j++) {
        if (powers[j] > maxBinVal) maxBinVal = powers[j];
      }
      fft8.push(Number(maxBinVal.toFixed(2)));
    }
  } else {
    for (let i = 0; i < NUM_BINS; i++) {
      const mappedIdx = Math.min(Math.floor((i / NUM_BINS) * N), N - 1);
      fft8.push(Number(powers[mappedIdx].toFixed(2)));
    }
  }

  return {
    deviceId: raw.deviceId,
    rssi: channelRssi,
    timestamp: normalizedTimestamp,
    fft: fft8,
  };
}

class CircularSignalBuffer {
  private buffer: RSSIPoint[];
  private head = 0;
  private count = 0;

  constructor(private readonly capacity: number = 120) {
    this.buffer = new Array(capacity);
  }

  push(pt: RSSIPoint): void {
    this.buffer[this.head] = pt;
    this.head = (this.head + 1) % this.capacity;
    if (this.count < this.capacity) this.count++;
  }

  getValidEntries(cutoff: number): RSSIPoint[] {
    const valid: RSSIPoint[] = [];
    for (let i = 0; i < this.count; i++) {
      const idx = (this.head - 1 - i + this.capacity) % this.capacity;
      const item = this.buffer[idx];
      if (item && item.t >= cutoff) {
        valid.push(item);
      }
    }
    return valid.sort((a, b) => a.t - b.t);
  }

  lastNMean(n: number): number {
    const samples = Math.min(n, this.count);
    if (samples === 0) return 0;
    let sum = 0;
    for (let i = 0; i < samples; i++) {
      const idx = (this.head - 1 - i + this.capacity) % this.capacity;
      sum += this.buffer[idx].rssi;
    }
    return sum / samples;
  }
}

interface BreachCandidate {
  type: "UPPER" | "LOWER";
  count: number;
  firstBreachTimestamp: number;
  lastUpdatedTimestamp: number;
  peakBins: number[];
}

export class POSSignalTracker {
  private buffers = new Map<string, CircularSignalBuffer>();
  private terminalStates = new Map<string, "SECURE" | "COMPROMISED">();
  private recoveryTimestamps = new Map<string, number>();
  private breachCandidates = new Map<string, BreachCandidate>();
  private lastActivityTimestamps = new Map<string, number>();

  private readonly WINDOW_SECONDS = 3.0;
  private readonly MIN_SAMPLES = 4;
  private readonly P_MAX = -38.0;
  private readonly P_MIN = -82.0;
  private readonly RECOVERY_REQUIRED_SEC = 2.0;
  private readonly UPPER_BREACH_THRESHOLD = 3;
  private readonly LOWER_BREACH_THRESHOLD = 12;
  private readonly CANDIDATE_EXPIRY_SEC = 10.0;
  private readonly DEVICE_INACTIVITY_TTL_SEC = 3600.0;
  private readonly MAX_TRACKED_DEVICES = 1000;

  private pruneInactiveDevices(currentTimestamp: number): void {
    if (this.lastActivityTimestamps.size < this.MAX_TRACKED_DEVICES) return;

    for (const [id, lastSeen] of this.lastActivityTimestamps.entries()) {
      if (currentTimestamp - lastSeen > this.DEVICE_INACTIVITY_TTL_SEC) {
        this.buffers.delete(id);
        this.terminalStates.delete(id);
        this.recoveryTimestamps.delete(id);
        this.breachCandidates.delete(id);
        this.lastActivityTimestamps.delete(id);
      }
    }
  }

  private analyzeFFT(fft: number[]): SpectralAnalysis {
    const bins = Array.isArray(fft) && fft.length === 8 ? fft : Array(8).fill(-65.0);
    let peakIndex = 0;
    let maxVal = -Infinity;
    let sumOther = 0;

    for (let i = 0; i < 8; i++) {
      const val = bins[i];
      if (val > maxVal) {
        maxVal = val;
        peakIndex = i;
      }
      sumOther += val;
    }

    const avgOther = (sumOther - maxVal) / 7;
    const spectralSpread = Number((maxVal - avgOther).toFixed(2));

    return {
      bins,
      peakBinIndex: peakIndex,
      peakBinPower: Number(maxVal.toFixed(2)),
      spectralSpreadDb: spectralSpread,
      isNarrowbandSpike: spectralSpread >= 18.0,
    };
  }

  public processReading(payload: POSTelemetryPayload): ProcessResult | null {
    const { deviceId, rssi } = payload;
    const timestamp = normalizeTimestamp(payload.timestamp);

    this.lastActivityTimestamps.set(deviceId, timestamp);
    this.pruneInactiveDevices(timestamp);

    let ring = this.buffers.get(deviceId);
    if (!ring) {
      ring = new CircularSignalBuffer(120);
      this.buffers.set(deviceId, ring);
    }
    ring.push({ t: timestamp, rssi });

    const series = ring.getValidEntries(timestamp - this.WINDOW_SECONDS);
    if (series.length < this.MIN_SAMPLES) return null;

    const currentMeanRssi = ring.lastNMean(3);
    const spectral = this.analyzeFFT(payload.fft);

    const isUpperBreach =
      currentMeanRssi > this.P_MAX ||
      (spectral.peakBinPower > this.P_MAX && spectral.isNarrowbandSpike);
    const isLowerBreach = currentMeanRssi < this.P_MIN;
    const isBreached = isUpperBreach || isLowerBreach;

    const currentState = this.terminalStates.get(deviceId) ?? "SECURE";

    if (currentState === "COMPROMISED") {
      if (!isBreached) {
        const firstSafeTime = this.recoveryTimestamps.get(deviceId) ?? timestamp;
        this.recoveryTimestamps.set(deviceId, firstSafeTime);

        if (timestamp - firstSafeTime >= this.RECOVERY_REQUIRED_SEC) {
          this.terminalStates.set(deviceId, "SECURE");
          this.recoveryTimestamps.delete(deviceId);
          this.breachCandidates.delete(deviceId);
          return { kind: "RECOVERED", deviceId: deviceId, recoveryTimestamp: timestamp };
        }
      } else {
        this.recoveryTimestamps.delete(deviceId);
      }
      return null;
    }

    const existingCandidate = this.breachCandidates.get(deviceId);
    if (
      existingCandidate &&
      timestamp - existingCandidate.lastUpdatedTimestamp > this.CANDIDATE_EXPIRY_SEC
    ) {
      this.breachCandidates.delete(deviceId);
    }

    if (!isBreached) {
      this.breachCandidates.delete(deviceId);
      this.recoveryTimestamps.delete(deviceId);
      return null;
    }

    const breachType: "UPPER" | "LOWER" = isUpperBreach ? "UPPER" : "LOWER";
    let candidate = this.breachCandidates.get(deviceId);

    if (!candidate || candidate.type !== breachType) {
      candidate = {
        type: breachType,
        count: 1,
        firstBreachTimestamp: timestamp,
        lastUpdatedTimestamp: timestamp,
        peakBins: [spectral.peakBinIndex],
      };
      this.breachCandidates.set(deviceId, candidate);
      return null;
    }

    candidate.count += 1;
    candidate.lastUpdatedTimestamp = timestamp;
    candidate.peakBins.push(spectral.peakBinIndex);

    const reqFrames =
      breachType === "LOWER" ? this.LOWER_BREACH_THRESHOLD : this.UPPER_BREACH_THRESHOLD;
    if (candidate.count < reqFrames) return null;

    if (breachType === "UPPER" && spectral.peakBinPower > this.P_MAX && spectral.isNarrowbandSpike) {
      const recent = candidate.peakBins.slice(-this.UPPER_BREACH_THRESHOLD);
      if (!recent.every((b) => b === recent[0])) {
        this.breachCandidates.delete(deviceId);
        return null;
      }
    }

    const sliceCount = breachType === "LOWER" ? this.LOWER_BREACH_THRESHOLD : 3;
    const actualSliceLen = Math.min(sliceCount, series.length);
    const activeSlice = series.slice(-actualSliceLen);

    let activeSum = 0;
    for (let i = 0; i < actualSliceLen; i++) {
      activeSum += activeSlice[i].rssi;
    }
    const activeMeanRssi = activeSum / actualSliceLen;

    let varSum = 0;
    for (let i = 0; i < actualSliceLen; i++) {
      varSum += Math.pow(activeSlice[i].rssi - activeMeanRssi, 2);
    }
    const activeVariance = varSum / actualSliceLen;

    let minRssi = Infinity;
    let maxRssi = -Infinity;
    for (let i = 0; i < series.length; i++) {
      const val = series[i].rssi;
      if (val < minRssi) minRssi = val;
      if (val > maxRssi) maxRssi = val;
    }

    const numIntervals = series.length - 1;
    const intervals: number[] = new Array(numIntervals);
    let intervalSum = 0;
    for (let i = 0; i < numIntervals; i++) {
      const diffMs = Math.round((series[i + 1].t - series[i].t) * 1000);
      intervals[i] = diffMs;
      intervalSum += diffMs;
    }
    intervals.sort((a, b) => a - b);

    const medianInterval = numIntervals > 0 ? intervals[Math.floor(numIntervals / 2)] : 0;
    const meanInterval = numIntervals > 0 ? intervalSum / numIntervals : 0;

    let intervalVarSum = 0;
    for (let i = 0; i < numIntervals; i++) {
      intervalVarSum += Math.pow(intervals[i] - meanInterval, 2);
    }
    const intervalStdDev = numIntervals > 0 ? Math.sqrt(intervalVarSum / numIntervals) : 0;

    const effectivePowerDbm = Math.max(activeMeanRssi, spectral.peakBinPower);
    const deltaDb = Number((effectivePowerDbm - this.P_MAX).toFixed(2));
    const powerSurgeRatio = deltaDb > 0 ? Number(Math.pow(10, deltaDb / 10).toFixed(1)) : 1.0;

    let likelyType: ThreatType = "FALSE_POSITIVE";
    if (isLowerBreach && !isUpperBreach) {
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

    if (likelyType === "FALSE_POSITIVE") {
      this.breachCandidates.delete(deviceId);
      this.recoveryTimestamps.delete(deviceId);
      return null;
    }

    this.terminalStates.set(deviceId, "COMPROMISED");
    this.breachCandidates.delete(deviceId);
    this.recoveryTimestamps.delete(deviceId);

    return {
      kind: "ALERT",
      deviceId: deviceId,
      metrics: {
        deviceId: deviceId,
        sampleCount: series.length,
        meanRssi: Number(activeMeanRssi.toFixed(2)),
        variance: Number(activeVariance.toFixed(2)),
        minRssi,
        maxRssi,
        isAttenuationBreach: isLowerBreach,
        medianIntervalMs: medianInterval,
        intervalStdDevMs: Math.round(intervalStdDev),
        durationSec: Number((series[series.length - 1].t - series[0].t).toFixed(2)),
        deltaDb,
        powerSurgeRatio,
        likelyType,
        rawSeries: series,
        spectral,
      },
    };
  }

  public manualReset(deviceId: string): void {
    this.terminalStates.set(deviceId, "SECURE");
    this.recoveryTimestamps.delete(deviceId);
    this.breachCandidates.delete(deviceId);
    this.buffers.delete(deviceId);
    this.lastActivityTimestamps.delete(deviceId);
  }
}