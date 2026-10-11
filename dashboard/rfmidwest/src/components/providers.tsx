// components/providers.tsx
'use client';

import { WebSocketProvider } from "@/hooks/webSocketConnection";
import Header from "@/components/header";
import { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <WebSocketProvider url="ws://127.0.0.1:3001/egress">
      <Header />
      {children}
    </WebSocketProvider>
  );
}