"use client";
import dynamic from "next/dynamic";

const Workbench = dynamic(() => import("@/ui/Workbench").then((m) => m.Workbench), { ssr: false, loading: () => <div className="flex h-screen items-center justify-center bg-[#0b0f17] text-zinc-500">Loading workbench…</div> });
const WorkbenchProvider = dynamic(() => import("@/ui/store").then((m) => m.WorkbenchProvider), { ssr: false });

export function WorkbenchClient() {
  return (
    <WorkbenchProvider>
      <Workbench />
    </WorkbenchProvider>
  );
}
