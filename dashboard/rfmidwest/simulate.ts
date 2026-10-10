// simulate.ts
const WS_URL = process.env.TARGET_WS_URL || "ws://localhost:3000/ingest";
const DEVICE_ID = "pos_terminal_01";

const socket = new WebSocket(WS_URL);

type SimMode =
  | "BASELINE"
  | "SHIMMER_ATTACK"
  | "SHIELDING_ATTACK"
  | "NFC_PHONE_TAP"
  | "CLEAN_CARD_TX";

let currentMode: SimMode = "BASELINE";
let transientFramesRemaining = 0;

// Pre-generate the 201 frequency bin keys (47.20M to 49.20M in 0.01 MHz steps)
const FREQ_KEYS: string[] = [];
for (let f = 4720; f <= 4920; f++) {
  FREQ_KEYS.push(`${(f / 100).toFixed(2)}M`);
}

socket.onopen = () => {
  console.log(`Connected to Ingest Socket: ${WS_URL}`);
  console.log("\n--- SDR Hardware Simulator Controls ---");
  console.log("Press [1] -> BASELINE (Ambient floor @ -54 to -58 dBm)");
  console.log("Press [2] -> ATTACK: ROGUE SHIMMER (Continuous 48.78 MHz spike @ -24.5 dBm)");
  console.log("Press [3] -> ATTACK: SHIELDING / TAMPER (All bins drop to -92 dBm)");
  console.log("Press [4] -> NORMAL ACTION: Phone Tap / NFC (200ms wideband transient burst)");
  console.log("Press [5] -> NORMAL ACTION: Legitimate EMV Chip Card (1.8s transaction @ -45 dBm)");
  console.log("Press [Ctrl+C] -> Exit\n");

  setInterval(streamData, 100);
};

socket.onmessage = (event) => {
  try {
    const data = JSON.parse(event.data.toString());
    if (data.event === "INCIDENT_ALERT") {
      console.log(
        `\n\x1b[31m[ALERT TRIGGERED]\x1b[0m ${data.verdict?.threat_type} | Action: ${data.verdict?.action} | Confidence: ${(data.verdict?.confidence * 100).toFixed(0)}%`
      );
    } else if (data.event === "STATUS_RECOVERED") {
      console.log(
        `\n\x1b[32m[STATUS RECOVERED]\x1b[0m Terminal ${data.deviceId} restored to ${data.status}`
      );
    }
  } catch {
    // Non-JSON or debug frame
  }
};

function generateSpectrum(): {
  spectrum: Record<string, number>;
  peakFreq: string;
  peakVal: number;
  approxRssi: number;
} {
  const spectrum: Record<string, number> = {};
  let peakFreq = FREQ_KEYS[0];
  let peakVal = -Infinity;
  let sumLinearMilliwatts = 0;

  for (const freqStr of FREQ_KEYS) {
    const freqMhz = parseFloat(freqStr.replace("M", ""));
    let powerDbm: number;

    if (currentMode === "SHIMMER_ATTACK") {
      // Sustained parasitic coupling on 48.78 MHz clock harmonic
      const noise = -56.0 + (Math.random() * 4.0 - 2.0);
      const centerFreq = 48.78;
      const bandwidth = 0.03;
      const dist = Math.abs(freqMhz - centerFreq);
      const spikePower = -24.5; // Breaches P_MAX (-38.0 dBm)

      if (dist < 0.08) {
        const attenuation = Math.exp(-Math.pow(dist / bandwidth, 2));
        powerDbm = noise + (spikePower - noise) * attenuation;
      } else {
        powerDbm = noise;
      }
    } else if (currentMode === "SHIELDING_ATTACK") {
      // Physical copper envelope / severed trace
      powerDbm = -93.0 + (Math.random() * 3.0 - 1.5);
    } else if (currentMode === "NFC_PHONE_TAP") {
      // Transient wideband burst: smartphone close-field coupling & hopping EMI
      // Random wandering center frequency simulates multipath/jitter
      const jitterCenter = 47.8 + Math.random() * 1.0;
      const dist = Math.abs(freqMhz - jitterCenter);
      const burstPeak = -32.0 + (Math.random() * 4.0 - 2.0); // Breaches power, but unstable & <300ms

      const attenuation = Math.exp(-Math.pow(dist / 0.25, 2));
      const baseNoise = -55.0 + (Math.random() * 4.0 - 2.0);
      powerDbm = baseNoise + (burstPeak - baseNoise) * attenuation;
    } else if (currentMode === "CLEAN_CARD_TX") {
      // Legitimate card inserted: ISO/IEC 7816-3 contact clock lines active
      // Emits on 48.78 MHz, but sits safely below P_MAX (-38.0 dBm) at -45.0 dBm
      const noise = -56.0 + (Math.random() * 4.0 - 2.0);
      const centerFreq = 48.78;
      const bandwidth = 0.03;
      const dist = Math.abs(freqMhz - centerFreq);
      const legitPower = -45.0; // Clean baseline power

      if (dist < 0.08) {
        const attenuation = Math.exp(-Math.pow(dist / bandwidth, 2));
        powerDbm = noise + (legitPower - noise) * attenuation;
      } else {
        powerDbm = noise;
      }
    } else {
      // Standard baseline noise
      powerDbm = -55.5 + (Math.random() * 4.5 - 2.25);
    }

    const val = Number(powerDbm.toFixed(2));
    spectrum[freqStr] = val;

    if (val > peakVal) {
      peakVal = val;
      peakFreq = freqStr;
    }

    sumLinearMilliwatts += Math.pow(10, val / 10);
  }

  // Handle auto-reversion for transient normal actions
  if (transientFramesRemaining > 0) {
    transientFramesRemaining--;
    if (transientFramesRemaining === 0) {
      currentMode = "BASELINE";
    }
  }

  const meanMilliwatts = sumLinearMilliwatts / FREQ_KEYS.length;
  const approxRssi = Number((10 * Math.log10(meanMilliwatts)).toFixed(2));

  return { spectrum, peakFreq, peakVal, approxRssi };
}

function streamData() {
  if (socket.readyState !== WebSocket.OPEN) return;

  const { spectrum, peakFreq, peakVal, approxRssi } = generateSpectrum();

  const payload = {
    device_id: DEVICE_ID,
    timestamp: Number((Date.now() / 1000).toFixed(2)),
    spectrum,
  };

  socket.send(JSON.stringify(payload));

  process.stdout.write(
    `\r[${currentMode.padEnd(16)}] RSSI: ${approxRssi.toFixed(1).padStart(6)} dBm | Peak: ${peakVal.toFixed(1)} dBm @ ${peakFreq}   `
  );
}

if (process.stdin.isTTY) {
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");

  process.stdin.on("data", (key: string) => {
    if (key === "\u0003") process.exit();
    if (key === "1") {
      currentMode = "BASELINE";
      transientFramesRemaining = 0;
      console.log("\n\n>>> Mode: BASELINE");
    }
    if (key === "2") {
      currentMode = "SHIMMER_ATTACK";
      transientFramesRemaining = 0;
      console.log("\n\n>>> Mode: ROGUE SHIMMER (Continuous 48.78 MHz Spike)");
    }
    if (key === "3") {
      currentMode = "SHIELDING_ATTACK";
      transientFramesRemaining = 0;
      console.log("\n\n>>> Mode: SHIELDING ATTACK (Faraday cage / trace cut)");
    }
    if (key === "4") {
      currentMode = "NFC_PHONE_TAP";
      transientFramesRemaining = 2; // 2 frames @ 10 Hz = 200 ms
      console.log("\n\n>>> Triggered: CONTACTLESS PHONE TAP (200ms transient wideband burst)");
    }
    if (key === "5") {
      currentMode = "CLEAN_CARD_TX";
      transientFramesRemaining = 18; // 18 frames @ 10 Hz = 1.8s transaction
      console.log("\n\n>>> Triggered: LEGITIMATE EMV CHIP CARD INSERTION (1.8s active transaction)");
    }
  });
}