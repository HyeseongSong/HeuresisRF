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
* **Cloud Hosting**: Akamai Cloud / Linode
* **Runtime**: Bun.js (Single-process monolith hosting native WebSockets & HTTP)
* **Ingestion & Streaming Layer**: Bi-directional WebSockets (/ingest SDR telemetry, /egress pub/sub dashboard stream)
* **Analytics & DSP Engine**: Custom state-latched hardware bounds evaluator with asymmetric persistence filtering & carrier stability analysis
* **AI Forensics**: Akamai Cloud Hosted AI (Qwen3.8 27b) with deterministic offline PCI fallback
* **Database & ORM**: Linode Managed PostgreSQL with Drizzle ORM (drizzle-orm/bun-sql)
* **Dashboard Framework**: Next.js (Tailwind CSS, Recharts)

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
```

## Cloud Backend Setup

### 1. Environment Configuration
Create a `.env` file in the project root containing your Linode PostgreSQL credentials and Akamai Hosted AI inference keys:

```env
PORT=3000
NODE_ENV=production
# Linode Managed PostgreSQL Connection String
DATABASE_URL="postgres://linode_user:your_password@linode-pg-cluster.linode.com:5432/rf_sentinel?sslmode=require"

# Akamai Cloud Hosted AI Inference Endpoint
AGENT_ENDPOINT_URL="[https://api.linode.com/v4/ai/inference](https://api.linode.com/v4/ai/inference)"
AGENT_API_KEY="your_linode_akamai_token_here"
AGENT_MODEL="chosen-model"
```

### 2. Dependency Installation & Database Migration
Install project dependencies with Bun and push the Drizzle schema directly to your Linode PostgreSQL instance:

```bash
bun install
bunx drizzle-kit push
```

### 3. Build & Production Launch
Set the target IP for hosting, build the Next.js frontend assets, bind the websocket server to 0.0.0.0 on port 3001, and launch both servers:

```bash
# Set the url parameter of WebSocketProvider to ws://<your target host ip>:3001/egress
nano ./dashboard/rfmidwest/src/components/providers.tsx
bun run build
bun run start
```
