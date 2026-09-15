export const DEFAULT_LAYOUT = { left: 300, right: 360, bottom: 170, showLeft: true, showRight: true, showBottom: true };
export function readLayout(): typeof DEFAULT_LAYOUT {
  try {
    const saved = JSON.parse(localStorage.getItem("rw.layout.v1") ?? "null");
    if (!saved || typeof saved !== "object") return { ...DEFAULT_LAYOUT };
    const size = (key: "left" | "right" | "bottom", min: number, max: number) => typeof saved[key] === "number" && Number.isFinite(saved[key]) ? Math.max(min, Math.min(max, saved[key])) : DEFAULT_LAYOUT[key];
    return { left: size("left", 200, 700), right: size("right", 260, 800), bottom: size("bottom", 80, 500), showLeft: typeof saved.showLeft === "boolean" ? saved.showLeft : true, showRight: typeof saved.showRight === "boolean" ? saved.showRight : true, showBottom: typeof saved.showBottom === "boolean" ? saved.showBottom : true };
  } catch { return { ...DEFAULT_LAYOUT }; }
}
