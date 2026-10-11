'use client';

import React, { createContext, useContext, ReactNode } from 'react';
import { useWebSocket } from '@/hooks/useWebSockets';

interface WebSocketContextType {
  isConnected: boolean;
  lastMessage: any | null;
  connect: () => void;
  disconnect: () => void;
}

export interface TelemetryPayload {
  event: 'TELEMETRY_POINT';
  deviceId: string;
  rssi: number;
  spectrum: Record<string, number>;
  fft: number[];
  timestamp: number;
}

export interface HeuristicAlertPayload {
  event: 'HEURISTIC_ALERT_TRIGGERED';
  deviceId: string;
  timestamp: number;
  status: string;
  heuristic: {
    likelyType: string;
    isAttenuationBreach: boolean;
    meanRssi: number;
    variance: number;
    deltaDb: number;
    powerSurgeRatio: number;
    dominantHarmonic: {
      binIndex: number;
      powerDbm: number;
      spectralSpreadDb: number;
      isNarrowbandSpike: boolean;
    };
    fft: number[];
    sampleCount: number;
    durationSec: number;
  };
}

export interface IncidentAlertPayload {
  event: 'INCIDENT_ALERT';
  incidentId: number;
  deviceId: string;
  timestamp: number;
  status: string;
  verdict: {
    threat_type: string;
    confidence: number;
    compromised_vector: string;
    risk_level: string;
    risk_justification: string;
    pci_containment_action: string;
    action: string;
    threat_diagnosis: string[];
    forensic_analysis: string;
    pci_compliance_impact: string;
    rationale: string;
  };
}

export interface StatusRecoveredPayload {
  event: 'STATUS_RECOVERED';
  incidentId?: number;
  deviceId: string;
  status: string;
  reason: string;
  rssi: number;
  timestamp: number;
}

export interface IngestStatusChangePayload {
  event: 'INGEST_STATUS_CHANGE';
  status: string;
  deviceId: string;
  activeIngestCount: number;
  timestamp: number;
}

// Combine them into a single union type
export type WebSocketMessage =
  | TelemetryPayload
  | HeuristicAlertPayload
  | IncidentAlertPayload
  | StatusRecoveredPayload
  | IngestStatusChangePayload;

const WebSocketContext = createContext<WebSocketContextType | null>(null);

interface WebSocketProviderProps {
  url: string;
  children: ReactNode;
}

export function WebSocketProvider({ url, children }: WebSocketProviderProps) {
  // Uses the hook internally to maintain one single persistent connection
  const webSocketState = useWebSocket({
    url,
    onConnect: () => console.log('Shared WebSocket connection established'),
    onDisconnect: () => console.log('Shared WebSocket connection lost'),
  });

  return (
    <WebSocketContext.Provider value={webSocketState}>
      {children}
    </WebSocketContext.Provider>
  );
}

// Custom hook for other files to look to for the single connection
export function useSharedWebSocket() {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useSharedWebSocket must be used within a WebSocketProvider');
  }
  return context;
}