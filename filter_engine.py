from collections import deque
from typing import Dict, Any

class RFBoundsEngine:
    """
    DSP Moving Average Filter and Deterministic Threshold Engine.
    Filters transient RF noise spikes and flags rogue transmitters or shielding attacks.
    """
    def __init__(self, window_size: int = 5, p_max: float = -30.0, p_min: float = -50.0):
        self.window_size = window_size
        self.p_max = p_max  # Rogue transmitter bound (dBm)
        self.p_min = p_min  # Physical shielding / Faraday bound (dBm)
        self.buffer = deque(maxlen=window_size)

    def process_reading(self, raw_rssi: float) -> Dict[str, Any]:
        """
        Ingests a raw dBm reading, updates the sliding window,
        and evaluates deterministic bounds.
        """
        self.buffer.append(raw_rssi)
        smoothed_rssi = round(sum(self.buffer) / len(self.buffer), 2)

        breach = False
        attack_type = "NOMINAL"

        if smoothed_rssi >= self.p_max:
            breach = True
            attack_type = "ROGUE_TRANSMITTER"
        elif smoothed_rssi <= self.p_min:
            breach = True
            attack_type = "SHIELDING_ATTACK"

        return {
            "raw_rssi": raw_rssi,
            "smoothed_rssi": smoothed_rssi,
            "breach": breach,
            "attack_type": attack_type,
            "p_max": self.p_max,
            "p_min": self.p_min
        }