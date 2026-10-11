// components/providers.tsx
'use client';

import { WebSocketProvider } from "@/hooks/webSocketConnection";
import Header from "@/components/header";
import { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <WebSocketProvider url="ws://173.255.199.123:3001/egress">
      <Header />
      {children}
    </WebSocketProvider>
  );
}