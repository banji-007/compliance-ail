import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Nav } from "@/components/nav";
import { Providers } from "./providers";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "AIL CISO Control Plane",
  description:
    "Agentic Integrity Ledger — Phase 3 CISO Dashboard. Policy configuration and cryptographic audit ledger for AI agent compliance.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <Providers>
          <div className="flex min-h-screen">
            <Nav />
            <main className="flex-1 overflow-auto p-8">{children}</main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
