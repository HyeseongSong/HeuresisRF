'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import { useSharedWebSocket, WebSocketMessage } from '@/hooks/webSocketConnection';

interface SpectrumPoint {
  mhz: number;
  dbm: number;
}

export default function Home() {
  const [isMounted, setIsMounted] = useState(false);
  const [spectrumData, setSpectrumData] = useState<SpectrumPoint[]>([]);
  const [peakRssi, setPeakRssi] = useState<number | null>(null);
  const [activeDeviceId, setActiveDeviceId] = useState<string>('pos_terminal_01');

  const { isConnected, lastMessage } = useSharedWebSocket();

  useEffect(() => {
    setIsMounted(true);
  }, []);

  // Ingest incoming FFT / Spectrum packets
  useEffect(() => {
    if (!lastMessage) return;

    const payload = lastMessage as any; // Cast loosely to support snake_case and camelCase

    if (payload.event === 'TELEMETRY_POINT') {
      if (payload.device_id || payload.deviceId) {
        setActiveDeviceId(payload.device_id || payload.deviceId);
      }

      if (typeof payload.rssi === 'number') {
        setPeakRssi(payload.rssi);
      }

      if (payload.spectrum && typeof payload.spectrum === 'object') {
        const parsed: SpectrumPoint[] = Object.entries(payload.spectrum)
          .map(([freqKey, powerVal]) => ({
            mhz: parseFloat(freqKey.replace(/M/i, '').trim()),
            dbm: Number(powerVal),
          }))
          // Must be sorted in ascending order for clean SVG rendering
          .sort((a, b) => a.mhz - b.mhz);

        if (parsed.length > 0) {
          setSpectrumData(parsed);
        }
      }
    }
  }, [lastMessage]);

  // Compute peak frequency bin dynamically
  const peakPoint = useMemo(() => {
    if (spectrumData.length === 0) return null;
    return spectrumData.reduce((prev, curr) => (curr.dbm > prev.dbm ? curr : prev));
  }, [spectrumData]);

  // Generate 200kHz interval ticks from 47.2 to 49.2 MHz
  const xTicks = useMemo(() => {
    const ticks: number[] = [];
    for (let f = 47.2; f <= 49.2; f = Number((f + 0.2).toFixed(2))) {
      ticks.push(f);
    }
    return ticks;
  }, []);

  return (
    <div className="flex flex-col flex-1 w-full bg-[#030712] text-zinc-100 min-h-screen">
      <main className="flex flex-col flex-1 w-full max-w-[1800px] mx-auto p-4 sm:p-6 gap-3">
        
        {/* Spectrum Top Status Ribbon */}
        <div className="flex items-center justify-between font-mono text-xs px-3 py-2 rounded-lg bg-zinc-950 border border-zinc-800/80 text-zinc-400">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-zinc-300 font-semibold uppercase">{activeDeviceId}</span>
            </span>
            <span className="text-zinc-600">|</span>
            <span>BANDWIDTH: <strong className="text-zinc-200">47.20 MHz – 49.20 MHz</strong></span>
            <span className="text-zinc-600">|</span>
            <span>RESOLUTION: <strong className="text-zinc-200">{spectrumData.length} BINS</strong></span>
          </div>

          <div className="flex items-center gap-4">
            {peakPoint && (
              <span>
                PEAK CARRIER: <strong className="text-cyan-400">{peakPoint.mhz.toFixed(2)} MHz</strong> ({peakPoint.dbm.toFixed(1)} dBm)
              </span>
            )}
            {peakRssi !== null && (
              <span>
                TOTAL RSSI: <strong className="text-emerald-400">{peakRssi.toFixed(2)} dBm</strong>
              </span>
            )}
          </div>
        </div>

        {/* SDR Spectrum Analyzer Window */}
        <div className="w-full h-[520px] rounded-xl bg-black border border-zinc-800/90 relative overflow-hidden flex flex-col p-2 shadow-2xl">
          {!isMounted || spectrumData.length === 0 ? (
            <div className="flex flex-col flex-1 items-center justify-center font-mono text-xs text-zinc-500 gap-3">
              <div className="h-2.5 w-2.5 rounded-full bg-cyan-500/80 animate-ping" />
              <span>{isConnected ? 'LIVE FEED SYNCED // ACQUIRING EM FFT FRAMES...' : 'GATEWAY DISCONNECTED'}</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={spectrumData} margin={{ top: 12, right: 16, left: -10, bottom: 0 }}>
                <defs>
                  {/* Subtle SDR Waterfall-style area fill under the spectrum trace */}
                  <linearGradient id="sdrGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                    <stop offset="60%" stopColor="#0891b2" stopOpacity={0.12} />
                    <stop offset="100%" stopColor="#0284c7" stopOpacity={0.02} />
                  </linearGradient>
                </defs>

                {/* Dark, subtle SDR measurement grid */}
                <CartesianGrid stroke="#1e293b" strokeDasharray="1 1" opacity={0.6} />

                {/* Frequency Domain X-Axis */}
                <XAxis
                  type="number"
                  dataKey="mhz"
                  domain={[47.2, 49.2]}
                  ticks={xTicks}
                  tickFormatter={(val) => `${val.toFixed(1)}M`}
                  stroke="#475569"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                  axisLine={{ stroke: '#334155' }}
                />

                {/* Power (dBm) Y-Axis */}
                <YAxis
                  type="number"
                  domain={[-95, 0]}
                  ticks={[0, -10, -20, -30, -40, -50, -60, -70, -80, -90]}
                  stroke="#475569"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                  axisLine={{ stroke: '#334155' }}
                  tickFormatter={(val) => `${val}`}
                />

                {/* SDR Tooltip */}
                <Tooltip
                  isAnimationActive={false}
                  contentStyle={{
                    backgroundColor: '#090d16',
                    borderColor: '#1e293b',
                    borderRadius: '0.375rem',
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: '#e2e8f0',
                  }}
                  formatter={(value: any) => [`${Number(value).toFixed(2)} dBm`, 'Power']}
                  labelFormatter={(label) => `${Number(label).toFixed(3)} MHz`}
                />

                {/* Spectrum Curve */}
                <Area
                  type="linear"
                  dataKey="dbm"
                  stroke="#38bdf8"
                  strokeWidth={1.2}
                  fill="url(#sdrGradient)"
                  isAnimationActive={false}
                  dot={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

      </main>
    </div>
  );
}