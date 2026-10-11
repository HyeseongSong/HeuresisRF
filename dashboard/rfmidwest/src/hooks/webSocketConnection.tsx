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
  event: string;
  device_id: string;
  rssi: number;
  spectrum: Record<string, number>; // For dynamic keys like "47.20M", "48.17M"
  fft: number[];
  timestamp: number;
}

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