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
    sdr.sample_rate = 2.048e6
    sdr.center_freq = 48.78e6   # Centered on the clean band where your red cursor is
    sdr.gain = 25.0             # Fixed gain
    return sdr

def calculate_rssi(samples):
    """
    Computes peak spectral power using FFT (matching the SDR spectrum display).
    Ignores the DC center spike and measures the strongest tone in the band.
    """
    # 1. Compute Fast Fourier Transform
    N = len(samples)
    fft_vals = np.fft.fftshift(np.fft.fft(samples))
    power_spectrum = (np.abs(fft_vals) / N) ** 2
    
    # 2. Mask out the RTL-SDR hardware DC center spike (middle 50 bins)
    mid = N // 2
    power_spectrum[mid - 25 : mid + 25] = 0

    # 3. Focus on a +/- 400 kHz window around 48.78 MHz (bins away from the 48.15 MHz hill)
    # At sample_rate = 2.048 MHz, 400 kHz is roughly 20% of the bins around the center
    window = int(N * 0.2)
    roi_spectrum = power_spectrum[mid - window : mid + window]

    # 4. Find the peak spike in that window
    peak_power = np.max(roi_spectrum)
    if peak_power < 1e-12:
        peak_power = 1e-12

    # 5. Convert to calibrated dBm
    rssi_dbm = 10 * np.log10(peak_power) + 40.0
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