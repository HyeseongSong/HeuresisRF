'use client';

import { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Radio, 
  Cpu, 
  Cloud, 
  Wifi, 
  WifiOff, 
  RotateCcw,
  Sparkles
} from 'lucide-react';
import { useSharedWebSocket } from '@/hooks/webSocketConnection';

export type TamperState = 'SECURE' | 'BREACH_UPPER' | 'BREACH_LOWER';

interface HeaderProps {
  status?: TamperState;
  deviceId?: string;
  isWsConnected?: boolean;
  currentRssi?: number | null;
  pMax?: number;
  pMin?: number;
  isAiAnalyzing?: boolean;
  onResetAlarm?: () => void;
}

export default function Header({
  status = 'SECURE',
  deviceId = 'pos_terminal_01',
  currentRssi = -58.4,
  pMax = -55.0,
  pMin = -85.0,
  isAiAnalyzing = false,
  onResetAlarm,
}: HeaderProps) {
  const isAlarm = status !== 'SECURE';

  // Prevent SSR evaluation crashes by verifying client mounting
  const [isMounted, setIsMounted] = useState(false);
  useEffect(() => {
    setIsMounted(true);
  }, []);

  const { isConnected, lastMessage } = useSharedWebSocket();

  // Safely fallback to prop default before initial WS frame arrives or during SSR
  const activeDeviceId = (isMounted && lastMessage?.device_id) ? lastMessage.device_id : deviceId;

  const formattedTimestamp = isMounted && lastMessage?.timestamp 
    ? new Date(lastMessage.timestamp * 1000).toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : 'AWAITING...';

  const getStatusBadge = () => {
    switch (status) {
      case 'BREACH_UPPER':
        return {
          title: 'TAMPER ALARM // ROGUE SHIMMER DETECTED',
          subtitle: `RF Spike Exceeded Pmax (${pMax} dBm)`,
          bgColor: 'bg-rose-950/80 border-rose-500 text-rose-200',
          pulseColor: 'bg-rose-500',
          icon: <ShieldAlert className="w-5 h-5 text-rose-400 animate-bounce" />,
        };
      case 'BREACH_LOWER':
        return {
          title: 'TAMPER ALARM // SHIELDING / CUT ANTENNA',
          subtitle: `Signal Dropped Below Pmin (${pMin} dBm)`,
          bgColor: 'bg-amber-950/80 border-amber-500 text-amber-200',
          pulseColor: 'bg-amber-500',
          icon: <ShieldAlert className="w-5 h-5 text-amber-400 animate-bounce" />,
        };
      case 'SECURE':
      default:
        return {
          title: 'SYSTEM SECURE // EM RUNTIME BOUNDS OK',
          subtitle: 'Active SDR Physical Layer Monitoring',
          bgColor: 'bg-emerald-950/60 border-emerald-500/70 text-emerald-200',
          pulseColor: 'bg-emerald-400',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
        };
    }
  };

  const statusConfig = getStatusBadge();

  return (
    <header className="sticky top-0 z-50 w-full border-b border-zinc-800 bg-zinc-950/90 backdrop-blur-md px-4 py-3 sm:px-6 transition-colors duration-300">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between max-w-[1720px] mx-auto">
        
        {/* Brand & Terminal Target */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-zinc-900 border border-zinc-700/80 shadow-inner">
            <Radio className={`w-5 h-5 ${isAlarm ? 'text-rose-400 animate-pulse' : 'text-cyan-400'}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs tracking-wider text-cyan-400 uppercase font-semibold">
                Hack Midwest 2026
              </span>
              <span className="text-zinc-600">/</span>
              <span className="font-mono text-xs text-zinc-400 uppercase tracking-widest">
                RFMidwest
              </span>
            </div>
            <h1 className="text-base font-bold tracking-tight text-zinc-100 flex items-center gap-2">
              RF-Sentinel
              <span className="text-xs font-mono font-normal text-zinc-400 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800">
                POS Physical-Layer Defense
              </span>
            </h1>
          </div>
        </div>

        {/* Primary Digital Status Badge */}
        <div className={`flex items-center justify-between sm:justify-start gap-4 px-4 py-2 rounded-xl border transition-all duration-300 shadow-lg ${statusConfig.bgColor}`}>
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center">
              <span className={`absolute inline-flex h-3 w-3 rounded-full opacity-75 animate-ping ${statusConfig.pulseColor}`} />
              <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${statusConfig.pulseColor}`} />
            </div>
            {statusConfig.icon}
            <div>
              <p className="font-mono text-xs sm:text-sm font-black tracking-wide uppercase">
                {statusConfig.title}
              </p>
              <p className="text-[11px] font-mono opacity-80">
                {statusConfig.subtitle}
              </p>
            </div>
          </div>

          {/* Reset / Silence Button */}
          {isAlarm && onResetAlarm && (
            <button
              onClick={onResetAlarm}
              className="ml-2 flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium rounded-md bg-zinc-900/90 text-zinc-200 border border-zinc-700 hover:bg-zinc-800 hover:text-white transition-all shadow"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset State
            </button>
          )}
        </div>

        {/* Diagnostics Pills */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          
          {/* Target Terminal Pill */}
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300">
            <Cpu className="w-3.5 h-3.5 text-zinc-400" />
            <span className="text-zinc-500">TARGET:</span>
            <span className="text-zinc-200 font-semibold">{activeDeviceId}</span>
          </div>

          {/* Live Timestamp Pill */}
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300">
            <span className="text-zinc-500">TS:</span>
            <span className="text-zinc-200 font-semibold">{formattedTimestamp}</span>
          </div>

          {/* Akamai Hosted Agent Pill */}
          <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border transition-all ${
            isAiAnalyzing 
              ? 'bg-amber-950/40 border-amber-600 text-amber-300 animate-pulse'
              : 'bg-zinc-900 border-zinc-800 text-zinc-300'
          }`}>
            <Sparkles className={`w-3.5 h-3.5 ${isAiAnalyzing ? 'text-amber-400' : 'text-blue-400'}`} />
            <Cloud className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-zinc-500">AKAMAI AGENT:</span>
            <span className={isAiAnalyzing ? 'text-amber-300 font-semibold' : 'text-zinc-200'}>
              {isAiAnalyzing ? 'INFERRING...' : 'READY'}
            </span>
          </div>

          {/* WebSocket Ingestion Link */}
          <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border ${
            isMounted && isConnected 
              ? 'bg-zinc-900 border-zinc-800 text-zinc-300' 
              : 'bg-rose-950/50 border-rose-800 text-rose-300'
          }`}>
            {isMounted && isConnected ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-zinc-500">GATEWAY:</span>
                <span className="text-emerald-400 font-semibold">LIVE</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-rose-400" />
                <span className="text-rose-400 font-semibold">OFFLINE</span>
              </>
            )}
          </div>

        </div>

      </div>
    </header>
  );
}