import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "soforge — native binary workbench",
  description: "Fast, AI-assisted ELF / .so reverse-engineering workbench for ARM64 and friends.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0b0f17] text-zinc-200 antialiased">{children}</body>
    </html>
  );
}
