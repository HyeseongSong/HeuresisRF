// src/hooks/useWebSockets.tsx
'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

interface UseWebSocketOptions {
  url: string;
  onMessage?: (data: any) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  reconnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export function useWebSocket({
  url,
  onMessage,
  onConnect,
  onDisconnect,
  onError,
  reconnect = true,
  reconnectInterval = 3000,
  maxReconnectAttempts = 5,
}: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Tracks explicit manual disconnection
  const isManuallyClosedRef = useRef(false);

  // Token to trigger fresh connection attempts via connect()
  const [connectToken, setConnectToken] = useState(0);

  // Keep latest callbacks in ref without triggering re-connects
  const callbacksRef = useRef({ onMessage, onConnect, onDisconnect, onError });
  useEffect(() => {
    callbacksRef.current = { onMessage, onConnect, onDisconnect, onError };
  }, [onMessage, onConnect, onDisconnect, onError]);

  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any | null>(null);

  useEffect(() => {
    // If the consumer manually called disconnect(), don't open until connect() is called
    if (isManuallyClosedRef.current) return;

    let socket: WebSocket | null = null;
    let didCancel = false;

    function openConnection() {
      if (didCancel || isManuallyClosedRef.current) return;

      try {
        console.log(`[WS CLIENT] Attempting connection to: ${url}`);
        socket = new WebSocket(url);
        wsRef.current = socket;

        socket.onopen = () => {
          if (didCancel) {
            socket?.close();
            return;
          }
          console.log('[WS CLIENT] Connection established successfully');
          setIsConnected(true);
          reconnectAttemptsRef.current = 0;
          callbacksRef.current.onConnect?.();
        };

        socket.onmessage = (event) => {
          console.log('[RAW WS INCOMING FRAME]:', event.data);
          if (didCancel) return;
          try {
            const parsedData = JSON.parse(event.data);
            setLastMessage(parsedData);
            callbacksRef.current.onMessage?.(parsedData);
          } catch (error) {
            console.error('[WS CLIENT] Failed to parse message JSON:', error);
          }
        };

        socket.onclose = (event) => {
          console.warn(`[WS CLIENT] Closed (code: ${event.code}, reason: "${event.reason}")`);
          wsRef.current = null;
          setIsConnected(false);

          // Only attempt reconnect if this wasn't an intentional cleanup or manual close
          if (!didCancel && !isManuallyClosedRef.current) {
            callbacksRef.current.onDisconnect?.();

            if (reconnect && reconnectAttemptsRef.current < maxReconnectAttempts) {
              reconnectAttemptsRef.current += 1;
              console.log(
                `[WS CLIENT] Reconnecting attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts} in ${reconnectInterval}ms...`
              );
              reconnectTimeoutRef.current = setTimeout(openConnection, reconnectInterval);
            }
          }
        };

        socket.onerror = (error) => {
          if (!didCancel) {
            console.error('[WS CLIENT] Error event:', error);
            callbacksRef.current.onError?.(error);
          }
        };
      } catch (err) {
        console.error('[WS CLIENT] Initialization error:', err);
      }
    }

    openConnection();

    return () => {
      didCancel = true;
      setIsConnected(false);

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }

      if (socket) {
        // Strip listeners before closing to prevent race condition callbacks during teardown
        socket.onopen = null;
        socket.onmessage = null;
        socket.onclose = null;
        socket.onerror = null;

        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
          socket.close();
        }
        socket = null;
      }
      wsRef.current = null;
    };
  }, [url, reconnect, reconnectInterval, maxReconnectAttempts, connectToken]);

  const disconnect = useCallback(() => {
    isManuallyClosedRef.current = true;

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setIsConnected(false);
  }, []);

  const connect = useCallback(() => {
    isManuallyClosedRef.current = false;
    reconnectAttemptsRef.current = 0;
    // Trigger the effect to open a new connection
    setConnectToken((prev) => prev + 1);
  }, []);

  const sendMessage = useCallback((data: unknown) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const payload = typeof data === 'string' ? data : JSON.stringify(data);
      wsRef.current.send(payload);
    } else {
      console.warn('[WS CLIENT] Cannot send message: WebSocket is not open.');
    }
  }, []);

  return { isConnected, lastMessage, connect, disconnect, sendMessage };
}