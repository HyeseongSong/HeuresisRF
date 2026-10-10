import ctypes
import time
import numpy as np

# ==============================================================================
# COMPATIBILITY SHIM: Prevent crashes on older rtlsdr.dll builds
# Catches missing DLL functions (bias_tee, dithering) and stubs them safely.
# ==============================================================================
_orig_getitem = ctypes.CDLL.__getitem__

def _safe_getitem(self, name):
    try:
        return _orig_getitem(self, name)
    except AttributeError:
        # Return a dummy callable function that returns 0 (success)
        return ctypes.CFUNCTYPE(ctypes.c_int)(lambda *args, **kwargs: 0)

ctypes.CDLL.__getitem__ = _safe_getitem
# ==============================================================================

# Now safe to import RtlSdr
from rtlsdr import RtlSdr

def setup_sdr():
    sdr = RtlSdr()
    sdr.sample_rate = 2.048e6   # 2.048 MS/s
    sdr.center_freq = 28.0e6    # 28 MHz (picks up massive low-frequency harmonics)
    sdr.gain = 35.0             # Fixed gain disables AGC compression!
    return sdr

def calculate_rssi(samples):
    # Normalized power relative to full scale (dBFS) scaled to simulated dBm
    power = np.mean(np.abs(samples) ** 2)
    if power < 1e-12:
        power = 1e-12
    # Baseline will sit around -50 to -60 dBm
    rssi_dbm = 10 * np.log10(power) + 10.0
    return round(float(rssi_dbm), 2)

def main():
    print("[*] Initializing RTL-SDR receiver...")
    try:
        sdr = setup_sdr()
    except Exception as e:
        print(f"[!] Error opening SDR: {e}")
        return

    print("[*] RTL-SDR successfully connected!")
    print("[*] Scanning baseline RF levels. Press Ctrl+C to terminate.")
    print("-" * 55)

    try:
        while True:
            # Read a batch of complex IQ samples
            samples = sdr.read_samples(1024 * 16)
            rssi = calculate_rssi(samples)
            
            # Simple terminal visualizer bar
            bar_length = max(0, int((rssi + 80) * 1.5))
            bar = "#" * bar_length
            
            print(f"RSSI: {rssi:>6.2f} dBm | {bar}")
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[*] Stopping SDR stream...")
    finally:
        sdr.close_device()
        print("[*] SDR device closed cleanly.")

if __name__ == "__main__":
    main()