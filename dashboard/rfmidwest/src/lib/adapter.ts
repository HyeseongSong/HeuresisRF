// lib/adapter.ts
export interface RawHardwarePayload {
  device_id: string;
  timestamp: number;
  spectrum?: Record<string, number>;
  rssi?: number;
  fft?: number[];
}

export interface POSTelemetryPayload {
  device_id: string;
  rssi: number;
  timestamp: number;
  fft: number[]; // 8-point downsampled FFT in dBm
}

export function parseHardwarePayload(raw: RawHardwarePayload): POSTelemetryPayload | null {
  if (!raw.device_id || typeof raw.timestamp !== "number") {
    return null;
  }

  // Backward compatibility with legacy mock payloads
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
  // Subtracting 10*log10(N) eliminates the +23 dB summation gain
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