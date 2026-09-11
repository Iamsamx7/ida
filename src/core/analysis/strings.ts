import type { StringCategory, StringEncoding, StringRecord } from "./types";

export interface RawString {
  addr: number;
  length: number;
  encoding: StringEncoding;
  value: string;
}

const isPrintable = (b: number) => (b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d;

/**
 * Scan a byte range for ASCII/UTF-8 and UTF-16LE strings.
 * Pure and worker-safe.
 */
export function scanStrings(bytes: Uint8Array, fileOffset: number, va: number, length: number, minLen = 4, maxCount = 2_000_000): RawString[] {
  const out: RawString[] = [];
  const end = Math.min(bytes.length, fileOffset + length);
  const utf8 = new TextDecoder("utf-8", { fatal: false });
  let i = fileOffset;
  while (i < end && out.length < maxCount) {
    const b = bytes[i];
    if (isPrintable(b) || b >= 0x80) {
      // ASCII / UTF-8 run
      let j = i;
      let ascii = true;
      let valid = true;
      while (j < end) {
        const c = bytes[j];
        if (c === 0) break;
        if (isPrintable(c)) { j++; continue; }
        if (c >= 0xc2 && c <= 0xf4) {
          const n = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : 1;
          let ok = j + n < end;
          for (let k = 1; ok && k <= n; k++) if ((bytes[j + k] & 0xc0) !== 0x80) ok = false;
          if (!ok) { valid = false; break; }
          ascii = false;
          j += n + 1;
          continue;
        }
        valid = false;
        break;
      }
      const runLen = j - i;
      if (runLen >= minLen && (valid || runLen >= minLen * 2)) {
        // Require termination or reasonable length to reduce noise from code bytes
        const terminated = j < end && bytes[j] === 0;
        if (terminated || runLen >= 8) {
          const slice = bytes.subarray(i, j);
          out.push({ addr: va + (i - fileOffset), length: runLen, encoding: ascii ? "ascii" : "utf8", value: utf8.decode(slice) });
        }
      }
      i = Math.max(j, i + 1);
      continue;
    }
    i++;
  }
  // UTF-16LE pass (only ASCII-range code units, common in Android/Windows-style resources)
  i = fileOffset;
  while (i + 1 < end && out.length < maxCount) {
    if (isPrintable(bytes[i]) && bytes[i + 1] === 0) {
      let j = i;
      while (j + 1 < end && isPrintable(bytes[j]) && bytes[j + 1] === 0) j += 2;
      const n = (j - i) / 2;
      if (n >= Math.max(minLen, 5) && j + 1 < end && bytes[j] === 0 && bytes[j + 1] === 0) {
        let s = "";
        for (let k = i; k < j; k += 2) s += String.fromCharCode(bytes[k]);
        out.push({ addr: va + (i - fileOffset), length: j - i, encoding: "utf16le", value: s });
      }
      i = Math.max(j, i + 2);
    } else i++;
  }
  out.sort((a, b) => a.addr - b.addr);
  return out;
}

const RX: [StringCategory, RegExp][] = [
  // Emulator fingerprints first: generic patterns below (config/path/command)
  // would otherwise swallow them (e.g. ro.product.model looks like config).
  ["anticheat", /(isEmulator|getEmulator|checkEmu|isEmu\b|emu[_-]?detect|anti[_-]?emu)/i],
  ["anticheat", /\b(mumu|memu|noxplayer|leapdroid|genymotion|youwave|andyos|remixos|phoenixos|primeos|vbox|virtualbox|goldfish|ranchu|ttvm|qemu)\b/i],
  ["anticheat", /ro\.(product\.(model|manufacturer|brand|device|board)|build\.(fingerprint|characteristics|product)|hardware|kernel\.qemu|boot\.qemu)|dev\/(qemu_pipe|socket\/qemud|qemu_trace)|qemu[-_]?props|ueventd\.(ranchu|goldfish)|init\.ranchu|fstab\.(ranchu|goldfish)|sys\/qemu_trace/i],
  ["anticheat", /000000000000000|1555521555\d?|310260000000000|sdk_gphone|google_sdk|Android SDK built for|android_x86|sdk_phone\b/i],
  ["url", /^(https?|wss?|ftp):\/\/|^[a-z0-9.-]+\.(com|net|org|io|cn|dev)(\/|$)/i],
  ["jni", /^Java_[A-Za-z0-9_]+|^\(L?[A-Za-z0-9_\/;\[]*\)[VZBCSIJFDL\[]|^L[a-z]+\/[A-Za-z0-9_\/$]+;?$/],
  ["path", /^(\/[A-Za-z0-9_.\-]+){2,}|\.(so|dex|apk|json|xml|cfg|ini|dat|bin|pak|txt|png|db)$|^\.\.?\//],
  ["crypto", /\b(AES|RSA|SHA-?(1|256|512)|MD5|HMAC|X509|PEM|BEGIN (RSA |EC )?(PUBLIC|PRIVATE) KEY|TLS|SSL|cipher|nonce|salt)\b/i],
  ["network", /\b(socket|connect|recv|send|http|packet|tcp|udp|dns|hostname|port|bind|listen|GET |POST |Content-Type|User-Agent)\b/i],
  ["error", /\b(error|failed|failure|invalid|cannot|couldn't|unable|exception|assert|abort|fatal|denied|corrupt|overflow|unexpected)\b/i],
  ["log", /^\[?[A-Z][A-Za-z]+\]?:|\b(debug|info|warn(ing)?|trace|verbose|log)\b|^%s[:=]|\bstarted|\bfinished/i],
  ["format", /%[-+ 0#]*\d*(\.\d+)?(hh|h|ll|l|z|j|t|L)?[diouxXeEfFgGaAcspn%]/],
  ["type-name", /^(_Z[NT]\w+|N\d+[A-Za-z_]\w*E|[A-Z][a-z]+([A-Z][a-z0-9]+){1,}(::\w+)*|std::|class |struct )/],
  ["config", /^[a-z_][a-z0-9_]*[._][a-z0-9_.]+$|\b(enable|disable|config|setting|option|default|timeout|max_|min_)\w*/i],
  ["command", /^(-{1,2}[a-z][a-z0-9-]*|[a-z]+( [a-z_-]+){0,2}=?)$|\b(exec|shell|cmd|su |chmod|mount|ptrace|dlopen|system\()/i],
  ["hash", /\b(md5|sha-?(1|224|256|384|512)|crc-?32|murmur|fnv|xxhash|checksum|digest|hmac|hash[_-]?verify|integrity[_-]?check)\b/i],
  ["anticheat", /\b(ban(ned)?|cheat|hack|aimbot|wallhack|esp|mod[_-]?menu|bypass|emulator|bluestacks|ldplayer|gameloop|gameguardian|gg_|libanogs|anosdk|tsssdk|aceanti|tp\s?sdk|safecheck|tracerpid|frida|gadget|magisk|xposed|substrate|edz\.so|anti[_-]?debug|debugger|tamper|root[_-]?check|su\s?binary|superuser)\b/i],
  ["game", /\b(revive|respawn|revival|resurrect|health|hp\b|heal|revive[_-]?coin|uc\b|diamond|player|teammate|knock(ed|down)?|finish[_-]?off|recall|parachute|zone|match[_-]?id|team[_-]?id|account[_-]?id|role[_-]?id|open_?id)\b/i],
];

export function categorize(value: string): StringCategory {
  for (const [cat, rx] of RX) if (rx.test(value)) return cat;
  return "generic";
}

export function toRecords(raw: RawString[]): StringRecord[] {
  return raw.map((r) => ({ ...r, category: categorize(r.value), refCount: 0 }));
}
