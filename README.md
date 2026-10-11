# HeuresisRF
**HackMidwest 2026**

HeuresisRF protects credit card readers from skimming by treating physical tampering as a measurable radio signal. Instead of relying on easily defeated tamper stickers, the system monitors a terminal's baseline electromagnetic emissions in real-time. When a thief implants a rogue device, the extra hardware alters the machine's energy signature. We capture that spike at the edge and stream it to the Akamai Cloud, where an AI instantly diagnoses the threat and generates a containment protocol. It replaces reactive, manual inspections with a proactive defense that catches hardware hacks the exact moment they occur.

---

## Tech Stack

### **Edge Sensing & Hardware**
* **Edge Processing Unit:** Raspberry Pi running Raspberry Pi OS (Bookworm) 
* **Software-Defined Radio (SDR):** Nooelec NESDR SMArt v5 (Rafael Micro R820T2 tuner)
* **Monitored Hardware:** POS Terminal / Microcontroller target (Arduino)

### **Edge Digital Signal Processing (DSP)**
* **Language/Runtime:** Python 3 (Virtual Environment)
* **SDR Interface:** `pyrtlsdr` (`librtlsdr` C driver bindings)
* **Spectral Analysis:** `scipy.signal` (Welch’s Power Spectral Density with 2048-bin Hann windowing)
* **Feature Extraction:** `numpy` (Max-Pooling array binning to preserve narrow ~20 kHz sideband comb spikes)
* **Transport Protocol:** `websockets` + `asyncio` (Real-time edge-to-cloud streaming)

### **Cloud Backend & Infrastructure**
* **Cloud Hosting:** Akamai Cloud Infrastructure
* **Ingestion Layer:** Asynchronous WebSocket Server
* **Analytics Engine:** Real-Time AI Spectral Anomaly Classifier & Automated Containment Protocol

---

## Hardware & Edge Setup

### 1. Physical Assembly
1. Connect the **Nooelec NESDR SMArt v5** SDR dongle to a USB port on the Raspberry Pi.
2. Position the SDR antenna adjacent to the target POS terminal’s main processing board or card reader IC to maximize RF coupling.

### 2. System Dependencies (Raspberry Pi)
Install the required system drivers and C libraries for RTL-SDR hardware access:

```bash
sudo apt update
sudo apt install -y git python3-venv python3-pip librtlsdr-dev rtl-sdr
