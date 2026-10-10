import ctypes
import time
import json
import asyncio
import numpy as np

# ==============================================================================
# COMPATIBILITY SHIM (Keep intact)
# ==============================================================================
_orig_getitem = ctypes.CDLL.__getitem__

def _safe_getitem(self, name):
    try:
        return _orig_getitem(self, name)
    except AttributeError:
        return ctypes.CFUNCTYPE(ctypes.c_int)(lambda *args, **kwargs: 0)

ctypes.CDLL.__getitem__ = _safe_getitem
# ==============================================================================

from rtlsdr import RtlSdr
import websockets

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


def calculate_rssi(samples):
    """
    Computes peak spectral power using FFT (matching the SDR spectrum display).
    Ignores the DC center spike and measures the strongest tone in the band.
    """
    N = len(samples)
    fft_vals = np.fft.fftshift(np.fft.fft(samples))
    power_spectrum = (np.abs(fft_vals) / N) ** 2
    
    mid = N // 2
    power_spectrum[mid - 25 : mid + 25] = 0

    window = int(N * 0.2)
    roi_spectrum = power_spectrum[mid - window : mid + window]

    peak_power = np.max(roi_spectrum)
    if peak_power < 1e-12:
        peak_power = 1e-12

    rssi_dbm = 10 * np.log10(peak_power) + 40.0
    return round(float(rssi_dbm), 2)


# ==============================================================================
# Edge-to-Cloud Asynchronous Streaming Loop
# ==============================================================================
async def stream_to_cloud():
    print("[*] Initializing RTL-SDR receiver...", flush=True)
    try:
        sdr = setup_sdr()
    except Exception as e:
        print(f"[!] Error opening SDR: {e}", flush=True)
        return

    print("[*] RTL-SDR successfully connected!", flush=True)
    print(f"[*] Target Cloud Server: {CLOUD_URL}", flush=True)

    while True:
        try:
            print("[*] Attempting to connect to Cloud WebSocket...", flush=True)
            async with websockets.connect(CLOUD_URL) as ws:
                print("[+] CONNECTED! Streaming live JSON packets to cloud...", flush=True)
                
                while True:
                    # 1. Capture IQ samples and compute dBm
                    samples = sdr.read_samples(1024 * 16)
                    rssi = calculate_rssi(samples)

                    # 2. Package into JSON schema
                    payload = {
                        "device_id": DEVICE_ID,
                        "rssi": rssi,
                        "timestamp": time.time()
                    }

                    # 3. Transmit JSON over WebSocket
                    await ws.send(json.dumps(payload))
                    print(f"[CLOUD TX] Sent: {json.dumps(payload)}", flush=True)
                    await asyncio.sleep(0.08)

        except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError, OSError):
            # Fallback if cloud server is offline
            samples = sdr.read_samples(1024 * 16)
            rssi = calculate_rssi(samples)
            print(f"[LOCAL BACKUP] RSSI: {rssi:>6.2f} dBm | Cloud disconnected, retrying...", flush=True)
            await asyncio.sleep(2.0)
            
        except Exception as e:
            print(f"[!] Error: {e}", flush=True)
            await asyncio.sleep(2.0)


if __name__ == "__main__":
    try:
        asyncio.run(stream_to_cloud())
    except KeyboardInterrupt:
        print("\n[*] Stopping SDR stream...", flush=True)
