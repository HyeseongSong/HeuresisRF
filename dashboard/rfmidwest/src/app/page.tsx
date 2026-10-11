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
import { useSharedWebSocket, IncidentAlertPayload, WebSocketMessage } from '@/hooks/webSocketConnection';

interface SpectrumPoint {
  mhz: number;
  dbm: number;
}

export default function Home() {
  const [isMounted, setIsMounted] = useState(false);
  const [spectrumData, setSpectrumData] = useState<SpectrumPoint[]>([]);
  const [peakRssi, setPeakRssi] = useState<number | null>(null);
  const [activeDeviceId, setActiveDeviceId] = useState<string>('pos_terminal_01');
  const [incidents, setIncidents] = useState<IncidentAlertPayload[]>([]);

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
    } else if (payload.event === 'INCIDENT_ALERT') {
      setIncidents((prevIncidents) => {
        // Optional: Prevent duplicate entries if the socket resends the same ID
        const exists = prevIncidents.some((inc) => inc.incidentId === payload.incidentId);
        if (exists) return prevIncidents;

        return [payload, ...prevIncidents];
      });
    }
  }, [lastMessage]);

  const getRiskBadgeColor = (risk: string) => {
    switch (risk?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    }
  };

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
              {/* Incident List Container */}
              <div className="max-w-4xl mx-auto space-y-4">
                {incidents.length === 0 ? (
                  <div className="text-center py-16 bg-slate-900/40 rounded-xl border border-slate-900">
                    <p className="text-slate-400 text-sm">No incidents recorded yet.</p>
                    <p className="text-slate-600 text-xs mt-1">Listening for incoming INCIDENT_ALERT payloads...</p>
                  </div>
                ) : (
                  incidents.map((incident) => (
                    <div
                      key={incident.incidentId}
                      className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg transition-all hover:border-slate-700"
                    >
                      {/* Card Header */}
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center space-x-3">
                          <span className="text-sm font-bold text-red-400 uppercase tracking-wide">
                            Incident #{incident.incidentId}
                          </span>
                          <span className="text-xs text-slate-400">
                            Device: <strong className="text-slate-200">{incident.deviceId}</strong>
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${getRiskBadgeColor(incident.verdict.risk_level)}`}>
                            {incident.verdict.risk_level}
                          </span>
                          <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
                            {incident.status}
                          </span>
                        </div>
                      </div>

                      {/* Threat Details */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950/50 p-4 rounded-lg border border-slate-800/60 mb-4">
                        <div>
                          <p className="text-xs text-slate-400">Threat Type</p>
                          <p className="text-sm font-semibold text-slate-200">{incident.verdict.threat_type}</p>
                        </div>
                        <div>
                          <p className="text-xs text-slate-400">Compromised Vector</p>
                          <p className="text-xs font-mono text-amber-400 mt-0.5">{incident.verdict.compromised_vector}</p>
                        </div>
                      </div>

                      {/* Justification */}
                      <p className="text-xs text-slate-300 mb-4 leading-relaxed">
                        {incident.verdict.risk_justification}
                      </p>

                      {/* Action Banner */}
                      <div className="bg-red-950/20 border border-red-500/20 p-3 rounded-lg flex items-center justify-between text-xs">
                        <div>
                          <span className="text-red-400 font-bold uppercase tracking-wider">Containment Action: </span>
                          <span className="text-slate-200 font-mono ml-1">{incident.verdict.pci_containment_action}</span>
                        </div>
                        <span className="bg-red-600 text-white font-bold px-3 py-1 rounded shadow">
                          {incident.verdict.action}
                        </span>
                      </div>

                      {/* Timestamp Footer */}
                      <div className="mt-4 pt-3 border-t border-slate-800/80 flex justify-end text-xs text-slate-500">
                        {new Date(incident.timestamp * 1000).toLocaleString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </ResponsiveContainer>
          )}
        </div>
      </main>
    </div>
  );
}