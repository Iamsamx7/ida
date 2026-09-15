import type { Classification, Evidence, FunctionFeatures } from "../types";
import { securityRules, DETECTION_LABELS } from "./securityRules";

/**
 * Modular rule engine for semantic classification.
 * Each rule inspects a FunctionContext and returns zero or more weighted hits
 * with evidence. Rules are data, not UI code: new classifiers are added by
 * pushing to `defaultRules` (or via the plugin API later).
 */
export interface FunctionContext {
  addr: number;
  name: string;
  size: number;
  features: FunctionFeatures;
  /** Names of called functions (imports resolved via PLT, symbols, or user names). */
  calleeNames: string[];
  callerNames: string[];
  stringValues: { addr: number; value: string; category: string }[];
  importsAll: Set<string>;
}

export interface RuleHit {
  label: string;
  weight: number; // 0..1 contribution
  evidence: Evidence;
}

export interface Rule {
  id: string;
  description: string;
  run(ctx: FunctionContext): RuleHit[];
}

const api = (patterns: RegExp, label: string, weight: number, id: string, description: string): Rule => ({
  id,
  description,
  run(ctx) {
    const hits: RuleHit[] = [];
    const seen = new Set<string>();
    for (const n of ctx.calleeNames) {
      const base = n.replace(/@.*$/, "");
      if (patterns.test(base) && !seen.has(base)) {
        seen.add(base);
        hits.push({ label, weight, evidence: { text: `calls ${base}`, certainty: "fact", address: ctx.addr } });
      }
    }
    return hits;
  },
});

const str = (patterns: RegExp, label: string, weight: number, id: string, description: string): Rule => ({
  id,
  description,
  run(ctx) {
    const hits: RuleHit[] = [];
    let n = 0;
    for (const s of ctx.stringValues) {
      if (patterns.test(s.value) && n < 3) {
        n++;
        hits.push({ label, weight, evidence: { text: `references string "${s.value.slice(0, 48)}"`, certainty: "fact", address: s.addr } });
      }
    }
    return hits;
  },
});

export const defaultRules: Rule[] = [
  ...securityRules,
  api(/^(malloc|calloc|realloc|free|posix_memalign|memalign|_Znwm|_Znam|_ZdlPv|_ZdaPv|operator new|operator delete|mmap|munmap|mprotect|madvise|malloc_usable_size|mallopt)$/, "memory-management", 0.45, "api.memory", "Heap / memory APIs"),
  api(/^(memcpy|memmove|memset|memcmp|bcopy|bzero|__memcpy_chk|__memmove_chk|__memset_chk|memchr|memrchr|explicit_bzero)$/, "memory-operations", 0.35, "api.memops", "Bulk memory operations (memcpy family)"),
  api(/^(strlen|strcmp|strncmp|strcpy|strncpy|strcat|strstr|strchr|strrchr|strtok|sprintf|snprintf|vsnprintf|sscanf|strtol|strtoul|strtod|atoi|toupper|tolower|isspace|isdigit|_ZNSt.*basic_string|__strlen_chk|strdup|strcasecmp|strncasecmp|strlcpy|strlcat)/, "string-processing", 0.4, "api.string", "C / C++ string APIs"),
  api(/^(open|openat|read|write|close|fopen|fclose|fread|fwrite|fseek|ftell|lseek|stat|fstat|lstat|access|mkdir|unlink|rename|opendir|readdir|fgets|fputs|fprintf|fflush|__open_2|ioctl)$/, "file-io", 0.5, "api.fileio", "File I/O APIs"),
  api(/^(socket|connect|bind|listen|accept|send|sendto|recv|recvfrom|getaddrinfo|gethostbyname|inet_ntop|inet_pton|setsockopt|getsockopt|poll|select|epoll_wait|epoll_ctl|shutdown|SSL_read|SSL_write|SSL_connect|curl_easy_perform|BIO_read|BIO_write|ntohl|htonl|ntohs|htons)$/, "networking", 0.55, "api.network", "Socket / TLS APIs"),
  api(/^(pthread_mutex_lock|pthread_mutex_unlock|pthread_cond_wait|pthread_cond_signal|pthread_cond_broadcast|pthread_rwlock_rdlock|pthread_rwlock_wrlock|pthread_rwlock_unlock|pthread_once|sem_wait|sem_post|__cxa_guard_acquire|__cxa_guard_release|pthread_spin_lock|futex)$/, "synchronization", 0.5, "api.sync", "Locking primitives"),
  api(/^(pthread_create|pthread_join|pthread_detach|pthread_self|pthread_setname_np|clone|fork|sched_yield|prctl)$/, "threading", 0.45, "api.thread", "Thread management"),
  api(/^(__android_log_print|__android_log_write|__android_log_vprint|__android_log_assert|syslog|vprintf|printf|puts|perror|fputs|__android_log_buf_write)$/, "logging", 0.5, "api.logging", "Logging APIs"),
  api(/^(AES_|EVP_|SHA1|SHA256|SHA512|MD5|HMAC|RAND_bytes|RSA_|EC_KEY|BN_|mbedtls_|CRYPTO_|sodium_|crypto_|arc4random)/, "cryptography", 0.6, "api.crypto", "Crypto library APIs"),
  api(/^(inflate|deflate|inflateInit|deflateInit|uncompress|compress2|LZ4_|ZSTD_|lzma_|BZ2_|zlib)/, "compression", 0.6, "api.compress", "Compression library APIs"),
  api(/^(gl[A-Z]\w+|egl[A-Z]\w+|vk[A-Z]\w+|ANativeWindow_|AHardwareBuffer_)/, "rendering", 0.55, "api.gfx", "Graphics APIs"),
  api(/^(dlopen|dlsym|dlclose|dladdr|android_dlopen_ext)$/, "dynamic-loading", 0.55, "api.dl", "Dynamic loader APIs"),
  api(/^(__cxa_throw|__cxa_begin_catch|__cxa_end_catch|__cxa_rethrow|_Unwind_Resume|__cxa_allocate_exception|abort|__stack_chk_fail|__assert2|__assert|raise|_ZSt9terminatev)$/, "error-handling", 0.35, "api.error", "Exception / abort APIs"),
  api(/^(ptrace|getppid|kill|sigaction|signal|inotify_init|inotify_add_watch|__system_property_get|uname|getauxval|syscall|process_vm_readv|process_vm_writev|getuid|geteuid|getgid|getpid|gettid|tkill|tgkill|exit|_exit|abort)$/, "integrity-check", 0.4, "api.antidebug", "Environment / integrity inspection APIs"),
  {
    id: "api.anticheat-sys",
    description: "Environment probes: strong ones (ptrace, property reads) count alone; generic file/string APIs only with anti-tamper or emulator strings in the same function",
    run(ctx) {
      const hits: RuleHit[] = [];
      const seen = new Set<string>();
      const corroborated = ctx.stringValues.some((s) => ANTI_TAMPER_STR.test(s.value));
      for (const n of ctx.calleeNames) {
        const base = n.replace(/@.*$/, "");
        if (seen.has(base)) continue;
        if (/^(ptrace|process_vm_readv|process_vm_writev|__system_property_get|getprop|inotify_add_watch|tgkill|tkill|prctl)$/.test(base)) { seen.add(base); hits.push({ label: "anticheat", weight: 0.35, evidence: { text: `calls ${base}`, certainty: "fact", address: ctx.addr } }); }
        else if (corroborated && /^(access|stat|fopen|fopen64|open|openat|open64|readlink|opendir|readdir|strstr|strcmp|strncmp)$/.test(base)) { seen.add(base); hits.push({ label: "anticheat", weight: 0.2, evidence: { text: `calls ${base} alongside anti-tamper/emulator strings`, certainty: "inference", address: ctx.addr } }); }
      }
      return hits;
    },
  },
  api(/^(JNI_OnLoad|Java_|_JNIEnv|AttachCurrentThread|GetEnv|FindClass|GetMethodID|CallObjectMethod|NewStringUTF|GetStringUTFChars|RegisterNatives)/, "jni-bridge", 0.5, "api.jni", "JNI bridge APIs"),
  api(/^(clock_gettime|gettimeofday|time|nanosleep|usleep|sleep|localtime|strftime|mktime|get_nsec|elapsedRealtime|uptimeMillis|SystemClock|QueryPerformanceCounter)$/, "timing", 0.4, "api.time", "Clock / timing APIs (gettimeofday family)"),
  {
    id: "api.ban-sys",
    description: "Report-and-punish syscalls — only meaningful next to ban vocabulary in the same function",
    run(ctx) {
      if (!ctx.stringValues.some((s) => BAN_STR.test(s.value))) return [];
      const hits: RuleHit[] = [];
      const seen = new Set<string>();
      for (const n of ctx.calleeNames) {
        const base = n.replace(/@.*$/, "");
        if (!seen.has(base) && /^(send|sendto|sendmsg|recv|recvfrom|recvmsg|write|__android_log_print|exit|_exit|kill|abort|pthread_exit)$/.test(base)) { seen.add(base); hits.push({ label: "ban-check", weight: 0.25, evidence: { text: `calls ${base} alongside ban vocabulary`, certainty: "inference", address: ctx.addr } }); }
      }
      return hits;
    },
  },
  api(/^(_ZN\w*(Serial|Deserial|Archive|Parse|Encode|Decode|Marshal|Unmarshal)\w*)/, "serialization", 0.45, "api.serial", "Serialization-looking symbols"),
  str(/^(https?|wss?):\/\//i, "networking", 0.35, "str.url", "URL strings"),
  str(/\b(socket|connect|recv|send|packet|tcp|udp|http|hostname)\b/i, "networking", 0.2, "str.net", "Network vocabulary"),
  str(/\.(so|dex|apk|json|xml|cfg|ini|dat|bin|pak|db)$|^\/(data|sdcard|system|proc|dev|storage)\//i, "file-io", 0.25, "str.path", "File paths"),
  str(/\b(error|failed|failure|invalid|cannot|couldn't|unable|exception|assert)\b/i, "error-handling", 0.2, "str.err", "Error vocabulary"),
  str(/\b(debug|verbose|trace|warn|info|log)\b|^\[%s\]|^%s:%d/i, "logging", 0.25, "str.log", "Log vocabulary"),
  str(/\b(AES|RSA|SHA|MD5|HMAC|cipher|nonce|salt|BEGIN (RSA |EC )?(PUBLIC|PRIVATE) KEY)\b/i, "cryptography", 0.3, "str.crypto", "Crypto vocabulary"),
  str(/\b(shader|texture|render|vertex|fragment|uniform|GL_|glsl|mesh|material|framebuffer)\b/i, "rendering", 0.3, "str.gfx", "Rendering vocabulary"),
  str(/\b(config|setting|option|preference|enable|disable|\.cfg|\.ini)\b/i, "configuration", 0.25, "str.cfg", "Configuration vocabulary"),
  str(/\b(serialize|deserialize|parse|decode|encode|unpack|pack|marshal)\b/i, "serialization", 0.25, "str.serial", "Serialization vocabulary"),
  str(/\b(init|initialize|initialise|startup|bootstrap|setup)\b/i, "initialization", 0.15, "str.init", "Initialization vocabulary"),
  str(/\b(touch|input|key(board|code|down|up)|gesture|pointer|gamepad|joystick|motion)\b/i, "input-handling", 0.3, "str.input", "Input vocabulary"),
  str(/(\broot(ed|ing|_?detect|_?check)?\b|\bsu\b|magisk|xposed|frida|substrate|tracerpid|\bdebugger\b|\btamper|checksum|signature verify)/i, "integrity-check", 0.35, "str.integrity", "Anti-tamper vocabulary"),
  str(/(\bban(ned|s)?\b|\bcheat|aimbot|wallhack|\besp\b|mod[_\- ]?menu|bypass|\bemulator|\b(bluestacks|ldplayer|gameloop)\b|gameguardian|libanogs|anosdk|tsssdk|aceanti|safecheck|anti[_\- ]?(cheat|hack|debug|tamper|emu)|debugger detected|tamper detected|security risk|violation|report[_\- ]?(cheat|violation)|punish)/i, "anticheat", 0.5, "str.anticheat", "Anti-cheat / emulator / ban vocabulary"),
  str(/(isEmulator|getEmulator|checkEmu|isEmu\b|emu[_-]?detect|anti[_-]?emu|\b(mumu|memu|nox|noxplayer|leapdroid|genymotion|youwave|andyos|remixos|phoenixos|primeos|vbox|virtualbox|goldfish|ranchu|ttvm|qemu|houdini|libhoudini|nativebridge|ndk_translation|smartgaga)\b|ro\.product\.|ro\.build\.fingerprint|ro\.build\.characteristics|ro\.hardware|ro\.kernel\.qemu|ro\.boot\.qemu|ro\.dalvik\.vm\.native\.bridge|dev\/qemu_pipe|dev\/socket\/qemud|qemu[-_]?props|ueventd\.(ranchu|goldfish|android_x86|vbox)|init\.ranchu|fstab\.(ranchu|goldfish|android_x86)|000000000000000|1555521555\d?|310260000000000|sdk_gphone|google_sdk|Android SDK built for|android_x86|game\s*simulator)/i, "anticheat", 0.55, "str.emu", "Emulator fingerprints: brands, build props, pipes, device IDs, verdict names"),
  str(/\b(account[_\- ]?(banned|blocked|suspended|frozen)|ban[_\- ]?(appeal|reason|code|duration|notice)|you have been banned|permanently (banned|suspended)|10[\- ]?year|封号|制裁)/i, "ban-check", 0.6, "str.ban", "Ban-notice vocabulary"),
  str(/\b(md5|sha-?(1|224|256|384|512)|crc-?32|murmur|fnv|xxhash|checksum|integrity[_\- ]?check|hash[_\- ]?verify|verify[_\- ]?(signature|hash|integrity)|signature[_\- ]?verify)\b/i, "hash-check", 0.5, "str.hashcheck", "Hash / integrity-verification vocabulary"),
  str(/\b(revive|revival|respawn|resurrect|recall|parachute|knock[ \-]?down|finish[ \-]?off|teammate|health|heal|revive[_\- ]?(coin|token)|self[_\- ]?revive)\b/i, "game-revive", 0.45, "str.revive", "Revive / respawn / game-state vocabulary"),
  str(/\b(world|player|actor|entity|scene|level|spawn|inventory|state machine|gamestate)\b/i, "state-management", 0.25, "str.state", "World/state vocabulary"),
  {
    id: "insn.crypto-like",
    description: "Dense rotate/xor/shift mix typical of hashing or cipher rounds",
    run(ctx) {
      const h = ctx.features.mnemonicHist;
      const total = Object.values(h).reduce((a, b) => a + b, 0) || 1;
      const mix = (h["eor"] ?? 0) + (h["ror"] ?? 0) + (h["extr"] ?? 0) + (h["xor"] ?? 0) + (h["rol"] ?? 0) + (h["lsr"] ?? 0) + (h["lsl"] ?? 0) + (h["shr"] ?? 0) + (h["shl"] ?? 0);
      const ratio = mix / total;
      if ((total > 40 && ratio > 0.28) || (total > 8 && ctx.features.hasLoop && ratio > 0.2)) {
        const label = ctx.features.constants.some((c) => CRYPTO_CONSTS.has(c >>> 0)) ? "cryptography" : "hashing";
        return [{ label, weight: Math.min(0.6, ratio), evidence: { text: `${Math.round(ratio * 100)}% of ${total} instructions are xor/rotate/shift`, certainty: "inference", address: ctx.addr } }];
      }
      return [];
    },
  },
  {
    id: "const.known",
    description: "Well-known algorithm constants",
    run(ctx) {
      const hits: RuleHit[] = [];
      for (const c of ctx.features.constants) {
        const k = c >>> 0;
        const name = KNOWN_CONSTS[k];
        if (name) hits.push({ label: name.label, weight: name.weight, evidence: { text: `uses constant 0x${k.toString(16)} (${name.desc})`, certainty: "fact", address: ctx.addr } });
      }
      return hits.slice(0, 4);
    },
  },
  {
    id: "insn.memcpy-like",
    description: "Load/store dominated loop → bulk copy / serialization",
    run(ctx) {
      const f = ctx.features;
      const total = Object.values(f.mnemonicHist).reduce((a, b) => a + b, 0) || 1;
      const ls = (f.loadCount + f.storeCount) / total;
      if (f.hasLoop && total > 30 && ls > 0.5 && f.callCount <= 1) {
        return [{ label: "serialization", weight: 0.3, evidence: { text: `loop with ${Math.round(ls * 100)}% load/store instructions and ${f.callCount} calls`, certainty: "inference", address: ctx.addr } }];
      }
      return [];
    },
  },
  {
    id: "struct.accessor",
    description: "Small function reading one or two fields → accessor / state reader",
    run(ctx) {
      const f = ctx.features;
      const total = Object.values(f.mnemonicHist).reduce((a, b) => a + b, 0) || 1;
      if (total <= 12 && f.loadCount >= 1 && f.storeCount === 0 && f.callCount === 0 && f.memAccessOffsets.length >= 1) {
        return [{ label: "state-access", weight: 0.45, evidence: { text: `${total}-instruction leaf function reading offset(s) ${f.memAccessOffsets.slice(0, 3).map((o) => "0x" + o.toString(16)).join(", ")}`, certainty: "inference", address: ctx.addr } }];
      }
      if (total <= 12 && f.storeCount >= 1 && f.callCount === 0 && f.memAccessOffsets.length >= 1 && f.loadCount <= 1) {
        return [{ label: "state-management", weight: 0.35, evidence: { text: `${total}-instruction leaf function writing field(s)`, certainty: "inference", address: ctx.addr } }];
      }
      return [];
    },
  },
  {
    id: "cfg.validation",
    description: "Many compare+branch pairs with few side effects → validation / bounds checking",
    run(ctx) {
      const f = ctx.features;
      const h = f.mnemonicHist;
      const cmp = (h["cmp"] ?? 0) + (h["cmn"] ?? 0) + (h["tst"] ?? 0) + (h["test"] ?? 0) + (h["cbz"] ?? 0) + (h["cbnz"] ?? 0) + (h["tbz"] ?? 0) + (h["tbnz"] ?? 0);
      const total = Object.values(h).reduce((a, b) => a + b, 0) || 1;
      if (total > 15 && cmp / total > 0.22 && f.storeCount / total < 0.1) {
        return [{ label: "validation", weight: 0.35, evidence: { text: `${cmp} compare/test instructions out of ${total} with few stores`, certainty: "inference", address: ctx.addr } }];
      }
      return [];
    },
  },
  {
    id: "combo.anticheat",
    description: "Anti-debug syscall + anti-tamper strings in the same function → likely anticheat check",
    run(ctx) {
      const sys = ctx.calleeNames.map((n) => n.replace(/@(plt|got)$/, "").replace(/@.*$/, "")).join(" ");
      const hasSys = /(ptrace|process_vm_readv|__system_property_get|getprop|inotify_add_watch|getppid|tkill|kill|open|openat|access|fopen|readlink|stat)/.test(sys);
      const strHit = ctx.stringValues.filter((s) => ANTI_TAMPER_STR.test(s.value) || /(telephony|\bdeviceid\b|subscriberid|line1number)/i.test(s.value));
      if (hasSys && strHit.length) return [{ label: "anticheat", weight: 0.7, evidence: { text: `combines integrity syscall with ${strHit.length} anti-tamper string(s), e.g. "${strHit[0].value.slice(0, 48)}"`, certainty: "inference", address: strHit[0].addr } }];
      if (strHit.length >= 2) return [{ label: "anticheat", weight: 0.55, evidence: { text: `${strHit.length} anti-cheat strings, e.g. "${strHit[0].value.slice(0, 48)}"`, certainty: "fact", address: strHit[0].addr } }];
      return [];
    },
  },
  {
    id: "combo.bancheck",
    description: "Ban vocabulary + reporting path (network/log/exit) → ban enforcement",
    run(ctx) {
      const banHit = ctx.stringValues.filter((s) => BAN_STR.test(s.value));
      if (!banHit.length) return [];
      const sys = ctx.calleeNames.join(" ");
      const reports = /(send|sendto|SSL_write|curl_easy_perform|BIO_write|Http|Request|report|__android_log_print|printf|exit|_exit|kill|abort)/.test(sys);
      const net = ctx.stringValues.some((s) => /https?:\/\//i.test(s.value));
      if (reports || net) return [{ label: "ban-check", weight: 0.65, evidence: { text: `ban string "${banHit[0].value.slice(0, 48)}" with network/log/exit reporting path`, certainty: "inference", address: banHit[0].addr } }];
      return [{ label: "ban-check", weight: 0.45, evidence: { text: `references ban string "${banHit[0].value.slice(0, 48)}"`, certainty: "fact", address: banHit[0].addr } }];
    },
  },
  {
    id: "combo.hashcheck",
    description: "Hash constants or crypto loop + compare/branch + verify strings → integrity/hash check",
    run(ctx) {
      const f = ctx.features;
      const h = f.mnemonicHist;
      const total = Object.values(h).reduce((a, b) => a + b, 0) || 1;
      const mix = (h["eor"] ?? 0) + (h["ror"] ?? 0) + (h["xor"] ?? 0) + (h["rol"] ?? 0) + (h["lsr"] ?? 0) + (h["lsl"] ?? 0) + (h["crc32"] ?? 0) + (h["crc32c"] ?? 0) + (h["sha256"] ?? 0) + (h["aes"] ?? 0);
      const cmp = (h["cmp"] ?? 0) + (h["cmn"] ?? 0) + (h["tst"] ?? 0) + (h["cbz"] ?? 0) + (h["cbnz"] ?? 0) + (h["test"] ?? 0);
      const verifyStr = ctx.stringValues.find((s) => /(verify|checksum|integrity|signature|tamper|hash|md5|sha|crc)/i.test(s.value));
      const knownConst = f.constants.some((c) => KNOWN_CONSTS[c >>> 0]);
      if ((f.hasLoop && mix / total > 0.15 && cmp >= 2) || (knownConst && cmp >= 1)) {
        return [{ label: "hash-check", weight: verifyStr ? 0.7 : 0.55, evidence: { text: verifyStr ? `hash-like loop (${Math.round((mix / total) * 100)}% bit-mix) with ${cmp} compare(s) near "${verifyStr.value.slice(0, 40)}"` : `hash-like loop (${Math.round((mix / total) * 100)}% bit-mix) with ${cmp} compare(s)`, certainty: "inference", address: verifyStr?.addr ?? ctx.addr } }];
      }
      if (verifyStr && /(memcmp|strcmp|strncmp|bcmp|CRYPTO_memcmp|Verify)/.test(ctx.calleeNames.join(" "))) {
        return [{ label: "hash-check", weight: 0.6, evidence: { text: `compares digest near "${verifyStr.value.slice(0, 40)}"`, certainty: "inference", address: verifyStr.addr } }];
      }
      return [];
    },
  },
  {
    id: "combo.revive",
    description: "Revive/respawn strings + state writes → game revive logic",
    run(ctx) {
      const rev = ctx.stringValues.filter((s) => /(revive|respawn|resurrect|recall|knock|finish[_\- ]?off|teammate|heal|revive[_\- ]?(coin|token))/i.test(s.value));
      if (!rev.length) return [];
      const f = ctx.features;
      const writes = f.storeCount >= 1 || /(write|send|Call|Set|Update|OnRevive|Respawn)/.test(ctx.calleeNames.join(" "));
      return [{ label: "game-revive", weight: writes ? 0.6 : 0.4, evidence: { text: `references revive string "${rev[0].value.slice(0, 48)}"${writes ? " with state write/call" : ""}`, certainty: writes ? "inference" : "fact", address: rev[0].addr } }];
    },
  },
  {
    id: "name.hints",
    description: "Symbol name vocabulary",
    run(ctx) {
      const n = ctx.name;
      if (/^(sub|loc|nullsub|j)_/.test(n)) return [];
      // Typeinfo names / typeinfo / vtables / VTTs are data, not behaviour — and `_ZTSSt…` contains "tss".
      if (/^_ZT[SIVT]/.test(n)) return [];
      const hits: RuleHit[] = [];
      const tbl: [RegExp, string][] = [
        [/init|setup|bootstrap|ctor|C1E|C2E|OnLoad/i, "initialization"],
        [/destroy|dtor|D0E|D1E|D2E|shutdown|cleanup|release|fini/i, "cleanup"],
        [/render|draw|shader|texture|mesh|gpu|frame/i, "rendering"],
        [/net|socket|packet|http|rpc|recv|send|connect/i, "networking"],
        [/alloc|free|pool|arena|heap/i, "memory-management"],
        [/serial|parse|decode|encode|marshal|read|write|load|save/i, "serialization"],
        [/hash|crc|digest|checksum/i, "hashing"],
        [/verify|integrity|checksum|tamper|hash/i, "hash-check"],
        [/anti[_-]?(cheat|hack|debug|tamper|emu)|cheat|\bhack|bypass|guard|protect|tsssdk|\btss\b|_tss|tss_|anogs|anosdk|\bano\b|safecheck/i, "anticheat"],
        [/emulator|isemu|qemu|goldfish|ranchu|\bvbox|genymotion|\bmumu\b|\bnox\b|virtualbox|\bldplayer\b|bluestacks/i, "anticheat"],
        [/\bban(ned|s)?\b|_ban_|punish|suspend|violation|report_?(cheat|violation|ban)/i, "ban-check"],
        [/revive|respawn|resurrect|recall|heal/i, "game-revive"],
        [/crypt|cipher|aes|rsa|sha|hmac|sign/i, "cryptography"],
        [/log|trace|debug|print/i, "logging"],
        [/lock|mutex|atomic|sync|barrier/i, "synchronization"],
        [/config|setting|option|pref/i, "configuration"],
        [/input|touch|key|gesture|pointer/i, "input-handling"],
        [/state|world|player|actor|entity|scene/i, "state-management"],
        [/verify|check|valid|assert|integrity|tamper|anti/i, "validation"],
        [/compress|inflate|deflate|zip|lz4|zstd/i, "compression"],
      ];
      for (const [rx, label] of tbl) if (rx.test(n)) hits.push({ label, weight: 0.3, evidence: { text: `symbol name "${n.slice(0, 60)}" contains ${label} vocabulary`, certainty: "inference", address: ctx.addr } });
      return hits.slice(0, 2);
    },
  },
];

/**
 * Anti-tamper / emulator vocabulary that lets generic file APIs count as probes
 * (shared by api.anticheat-sys, combo.anticheat and the intel proof legs).
 * Word-bounded where a bare token has innocent neighbours in game binaries:
 * `root` (RootComponent), `anti` (AntiAliasing), `su` (Sub…), `memu`
 * (VolumeMultiplier), `ldplayer` (WorldPlayer), `nox`.
 */
export const ANTI_TAMPER_STR = /(tracerpid|frida|magisk|xposed|substrate|\bemulator|isEmulator|getEmulator|checkEmu|isEmu\b|emu[_-]?detect|\b(bluestacks|ldplayer|gameloop|mumu|memu|nox|noxplayer|leapdroid|genymotion|youwave|vbox|virtualbox|goldfish|ranchu|ttvm|qemu|houdini|libhoudini|nativebridge|ndk_translation|smartgaga)\b|\bdebugger\b|\btamper|\bsu\b|\broot(ed|ing|_?detect|_?check)?\b|gameguardian|anogs|tsssdk|safecheck|anti[_\- ]?(cheat|hack|debug|tamper|emu)|ro\.product\.|ro\.build\.|ro\.hardware|ro\.kernel\.qemu|ro\.boot\.qemu|ro\.dalvik\.vm\.native\.bridge|dev\/qemu|qemu[-_]?props|ueventd\.|fstab\.|\/proc\/self\/(maps|status|mem)|\/proc\/\d+\/maps|000000000000000|1555521555|310260000000000|sdk_gphone|google_sdk|android_x86|game\s*simulator)/i;
/** Ban vocabulary (shared by api.ban-sys and combo.bancheck). `ban` is word-bounded: Banner, Urban, Bandwidth are not bans. */
export const BAN_STR = /(\bban(ned|s)?\b|suspend|violation|punish|封号|制裁|account.{0,12}(blocked|frozen))/i;

const CRYPTO_CONSTS = new Set<number>([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, 0x428a2f98, 0x71374491, 0x9e3779b9, 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0xcafebabe]);
const KNOWN_CONSTS: Record<number, { label: string; weight: number; desc: string }> = {
  0x67452301: { label: "hashing", weight: 0.6, desc: "MD5/SHA-1 IV" },
  0xefcdab89: { label: "hashing", weight: 0.6, desc: "MD5/SHA-1 IV" },
  0x98badcfe: { label: "hashing", weight: 0.6, desc: "MD5/SHA-1 IV" },
  0xc3d2e1f0: { label: "hashing", weight: 0.6, desc: "SHA-1 IV" },
  0x6a09e667: { label: "hashing", weight: 0.65, desc: "SHA-256 IV" },
  0xbb67ae85: { label: "hashing", weight: 0.65, desc: "SHA-256 IV" },
  0x428a2f98: { label: "hashing", weight: 0.65, desc: "SHA-256 round constant" },
  0x9e3779b9: { label: "hashing", weight: 0.4, desc: "golden ratio / TEA / hash mix" },
  0x811c9dc5: { label: "hashing", weight: 0.6, desc: "FNV-1 32-bit offset basis" },
  0x01000193: { label: "hashing", weight: 0.6, desc: "FNV prime" },
  0xedb88320: { label: "hashing", weight: 0.7, desc: "CRC-32 reversed polynomial" },
  0x04c11db7: { label: "hashing", weight: 0.7, desc: "CRC-32 polynomial" },
  0x82f63b78: { label: "hashing", weight: 0.7, desc: "CRC-32C polynomial" },
  0xcc9e2d51: { label: "hashing", weight: 0.6, desc: "MurmurHash3 c1" },
  0x1b873593: { label: "hashing", weight: 0.6, desc: "MurmurHash3 c2" },
  0x61707865: { label: "cryptography", weight: 0.7, desc: "ChaCha/Salsa 'expa'" },
  0x3320646e: { label: "cryptography", weight: 0.7, desc: "ChaCha/Salsa 'nd 3'" },
  0x9908b0df: { label: "hashing", weight: 0.4, desc: "Mersenne Twister" },
  0x5851f42d: { label: "hashing", weight: 0.4, desc: "PCG multiplier" },
  0x7f454c46: { label: "integrity-check", weight: 0.5, desc: "ELF magic" },
  0x464c457f: { label: "integrity-check", weight: 0.5, desc: "ELF magic (LE)" },
  0x6c62272e: { label: "hashing", weight: 0.4, desc: "FNV-1a 64 basis (hi)" },
  0x62d3a5a1: { label: "hashing", weight: 0.4, desc: "FNV-1a 64 basis (lo)" },
  0x9e3779b1: { label: "hashing", weight: 0.4, desc: "golden ratio (TEA delta)" },
  0x85ebca6b: { label: "hashing", weight: 0.6, desc: "MurmurHash3 fmix32" },
  0xc2b2ae35: { label: "hashing", weight: 0.6, desc: "MurmurHash3 fmix32" },
  0xff51afd7: { label: "hashing", weight: 0.55, desc: "MurmurHash3 fmix64" },
  0xc4ceb9fe: { label: "hashing", weight: 0.55, desc: "MurmurHash3 fmix64" },
  0x9fb21c65: { label: "hashing", weight: 0.55, desc: "xxHash32 prime1" },
  0xc2b2ae3d: { label: "hashing", weight: 0.55, desc: "xxHash32 prime2" },
  0x27d4eb2f: { label: "hashing", weight: 0.55, desc: "xxHash32 prime4" },
  0x165667b1: { label: "hashing", weight: 0.55, desc: "xxHash32 prime5" },
  0xd8000000: { label: "hashing", weight: 0.25, desc: "UTF-16 surrogate range (string decode loop)" },
};

export function classify(ctx: FunctionContext, rules: Rule[] = defaultRules): Classification[] {
  const byLabel = new Map<string, { notP: number; evidence: Evidence[] }>();
  for (const rule of rules) {
    let hits: RuleHit[];
    try {
      hits = rule.run(ctx);
    } catch {
      continue;
    }
    for (const h of hits) {
      const e = byLabel.get(h.label) ?? { notP: 1, evidence: [] };
      e.notP *= 1 - Math.max(0, Math.min(0.95, h.weight));
      if (e.evidence.length < 8) e.evidence.push(h.evidence);
      byLabel.set(h.label, e);
    }
  }
  const out: Classification[] = [];
  for (const [label, e] of byLabel) {
    const confidence = 1 - e.notP;
    if (confidence < 0.2) continue;
    out.push({ label, confidence, level: confidence >= 0.8 ? "high" : confidence >= 0.55 ? "likely" : confidence >= 0.35 ? "possible" : "low", evidence: e.evidence });
  }
  out.sort((a, b) => b.confidence - a.confidence);
  // Keep specific detections even when broad I/O/logging labels score higher.
  return out;
}

export const COMPONENT_LABELS = [
  ...DETECTION_LABELS,
  "memory-management", "memory-operations", "string-processing", "file-io", "networking", "serialization", "rendering", "input-handling",
  "state-management", "state-access", "cryptography", "hashing", "hash-check", "compression", "logging", "configuration", "initialization", "cleanup",
  "synchronization", "threading", "error-handling", "validation", "integrity-check", "anticheat", "ban-check", "game-revive", "jni-bridge", "dynamic-loading", "timing",
];
