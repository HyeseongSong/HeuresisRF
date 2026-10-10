import ctypes
import time
import json
import asyncio
import numpy as np

# --- DLL COMPATIBILITY SHIM ---
_orig_getitem = ctypes.CDLL.__getitem__
def _safe_getitem(self, name):
    try:
        return _orig_getitem(self, name)
    except AttributeError:
        return ctypes.CFUNCTYPE(ctypes.c_int)(lambda *args, **kwargs: 0)
ctypes.CDLL.__getitem__ = _safe_getitem
# ------------------------------

from rtlsdr import RtlSdr
import websockets

# URL of your local or Akamai Linode backend
# ==============================================================================
# CONFIGURATION: Set the URL of your cloud server
# Replace "localhost" with your Linode IP when ready:
# e.g., "ws://192.0.2.1:8000/ws/edge"
# ==============================================================================
CLOUD_URL = "ws://localhost:8000/ws/edge"
DEVICE_ID = "pos_terminal_01"

def setup_sdr():
    sdr = RtlSdr()
    sdr.sample_rate = 2.048e6
    sdr.center_freq = 48.16e6   # Calibrated 48.78 MHz harmonic
    sdr.gain = 25.0             # Fixed gain
    return sdr

def extract_rf_metrics(samples):
    N = len(samples)
    fft_vals = np.fft.fftshift(np.fft.fft(samples))
    power_spectrum = (np.abs(fft_vals) / N) ** 2
    
    mid = N // 2
    power_spectrum[mid - 25 : mid + 25] = 0  # Mask DC spike

    window = int(N * 0.2)
    roi_spectrum = power_spectrum[mid - window : mid + window]

    # 1. Peak power in dBm
    peak_power = np.max(roi_spectrum)
    if peak_power < 1e-12:
        peak_power = 1e-12
    rssi_dbm = round(float(10 * np.log10(peak_power) + 40.0), 2)

    # 2. Extract 8-bin mini spectrum slice for SDR++ style visualizer
    bin_size = len(roi_spectrum) // 8
    mini_spectrum = []
    for i in range(8):
        sub_slice = roi_spectrum[i * bin_size : (i + 1) * bin_size]
        sub_power = np.max(sub_slice) if len(sub_slice) > 0 else 1e-12
        sub_dbm = round(float(10 * np.log10(max(sub_power, 1e-12)) + 40.0), 1)
        mini_spectrum.append(sub_dbm)

    return rssi_dbm, mini_spectrum

async def stream_to_cloud():
    sdr = setup_sdr()
    print("[*] RTL-SDR initialized. Streaming 4Hz telemetry...")

    while True:
        try:
            async with websockets.connect(CLOUD_URL) as ws:
                print("[+] Connected to Backend!")
                while True:
                    samples = sdr.read_samples(1024 * 16)
                    rssi, spectrum = extract_rf_metrics(samples)

                    # 2. Package into JSON schema
                    payload = {
                        "device_id": DEVICE_ID,
                        "rssi": rssi,
                        "spectrum": spectrum,
                        "timestamp": round(time.time(), 2)
                    }

                    await ws.send(json.dumps(payload))
                    print(f"[TX] RSSI: {rssi:>6.2f} dBm", end="\r")
                    await asyncio.sleep(0.25) # 4 updates per second (every 250ms)

        except Exception:
            await asyncio.sleep(1.5)

if __name__ == "__main__":
    try:
        asyncio.run(stream_to_cloud())
    except KeyboardInterrupt:
        print("\n[*] Stopped cleanly.")
