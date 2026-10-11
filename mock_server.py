import asyncio
import json
import websockets

# Handler for incoming WebSocket connections from edge nodes

async def echo_handler(websocket):
    print(f"[+] Client connected: {websocket.remote_address}")
    try:
        async for message in websocket:
            # Parse incoming JSON payload
            data = json.loads(message)
            device_id = data.get("device_id", "unknown")
            timestamp = data.get("timestamp", 0)
            spectrum = data.get("spectrum", {})

            # ==================================================================
            # PUT IT HERE: Print the entire raw spectrum map
            # ==================================================================
            if spectrum:
                print(f"\n[CLOUD RX] {device_id} @ {timestamp}")
                print(f"Spectrum Map: {spectrum}")
            else:
                print(f"[CLOUD RX] Received message from {device_id}: {message}")
            # ==================================================================

    except websockets.exceptions.ConnectionClosed:
        print(f"[-] Client disconnected: {websocket.remote_address}")
    
    except websockets.exceptions.ConnectionClosed:
        print(f"[-] Client disconnected: {websocket.remote_address}")

async def main():
    # Bind to 0.0.0.0 to accept network requests from Raspberry Pi
    async with websockets.serve(echo_handler, "0.0.0.0", 8000):
        print("[*] Mock Cloud Server active on ws://0.0.0.0:8000")
        print("[*] Ready to receive telemetry from Raspberry Pi...")
        await asyncio.Future()  # Keep server running forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Stopping Mock Server...")
