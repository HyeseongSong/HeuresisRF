'use client';

import { useState, useEffect } from 'react';
import { CartesianGrid, Line, LineChart, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';
import { useSharedWebSocket, TelemetryPayload } from '@/hooks/webSocketConnection';

export default function Home() {
  const [isMounted, setIsMounted] = useState(false);
  const { isConnected, lastMessage } = useSharedWebSocket();

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const telemetry = lastMessage as TelemetryPayload | null;

  if (!telemetry) {
    return <div>Waiting for telemetry data...</div>;
  }

  // Safe fallback: uses empty object if spectrum is null/undefined during SSR or before first WS frame
  const data = Object.entries(telemetry?.spectrum ?? {}).map(([key, value]) => ({
    mhz: parseFloat(key.replace('M', '')), // Numeric float for Recharts numeric domain
    rssi: value,
  }));

  return (
    <div className="flex flex-col flex-1 items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="flex flex-1 w-full max-w-5xl flex-col items-center justify-center py-12 px-6 bg-white dark:bg-black">
        {!isMounted || data.length === 0 ? (
          <div className="w-full aspect-[1.618] max-w-[1200px] flex flex-col items-center justify-center border border-zinc-800 rounded-lg bg-zinc-950 font-mono text-xs text-zinc-500 gap-2">
            <span className="animate-pulse">
              {isConnected ? 'STREAM CONNECTED // AWAITING SDR SPECTRUM...' : 'AWAITING GATEWAY CONNECTION...'}
            </span>
          </div>
        ) : (
          <div className="w-full aspect-[1.618] max-w-[1200px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data}>
                <CartesianGrid strokeDasharray="5 5" stroke="#27272a" />
                <Line
                  type="monotone"
                  dataKey="rssi"
                  stroke="#38bdf8"
                  strokeWidth={2}
                  activeDot={false}
                  dot={false}
                  isAnimationActive={false}
                />
                <XAxis
                  type="number"
                  dataKey="mhz"
                  domain={[47.2, 49.2]}
                  unit="M"
                  tickCount={11}
                  stroke="#71717a"
                  tick={{ fill: '#71717a', fontSize: 11, fontFamily: 'monospace' }}
                />
                <YAxis
                  type="number"
                  dataKey="rssi"
                  domain={[-100, 0]}
                  unit=" dBm"
                  stroke="#71717a"
                  tick={{ fill: '#71717a', fontSize: 11, fontFamily: 'monospace' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#09090b',
                    borderColor: '#27272a',
                    borderRadius: '0.375rem',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                  }}
                  formatter={(value: any) => [`${value} dBm`, 'Power']}
                  labelFormatter={(label) => `${label} MHz`}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </main>
    </div>
  );
}