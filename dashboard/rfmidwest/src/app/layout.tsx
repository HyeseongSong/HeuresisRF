import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Header from "@/components/header"
import { WebSocketProvider } from "@/hooks/webSocketConnection";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "RFMidwest",
  description: "The dashboard for the RFMidwest project for Hack Midwest 2027!",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <WebSocketProvider url="placeholder/egress">
          <Header />
          {children}
        </WebSocketProvider>
      </body>
    </html>
  );
}
