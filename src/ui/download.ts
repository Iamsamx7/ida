/** Keep the object URL alive through the browser's download dispatch, then release it. */
export function downloadText(name: string, text: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_");
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
