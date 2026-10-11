// components/providers.tsx
"use client";

import type { ReactNode } from "react";
import Header from "@/components/header";
import { WebSocketProvider } from "@/hooks/webSocketConnection";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <WebSocketProvider url="ws://173.255.199.123:3001/egress">
      <Header />
      {children}
    </WebSocketProvider>
  );
}
