import type { Rule, FunctionContext } from "./rules";

export const DETECTION_LABELS = [
  "debugger-detection", "root-detection", "emulator-detection", "instrumentation-detection",
  "process-inspection", "tls-verification", "certificate-pinning", "signature-verification",
  "memory-permission-change", "secure-random", "secure-erasure", "native-registration",
] as const;

const baseName = (name: string) => name.replace(/@.*$/, "");
const called = (ctx: FunctionContext, pattern: RegExp) => [...new Set(ctx.calleeNames.map(baseName))].filter((n) => pattern.test(n));
const markers = (ctx: FunctionContext, pattern: RegExp) => {
  const seen = new Set<string>();
  return ctx.stringValues.filter((s) => {
    if (!pattern.test(s.value) || seen.has(s.value)) return false;
    seen.add(s.value); return true;
  });
};
const FILE_PROBE = /^(?:open(?:64|at)?|__open_2|fopen(?:64)?|access|faccessat|stat(?:64)?|lstat(?:64)?|readlink(?:at)?|opendir|readdir|read|fread|fgets)$/;
const PROPERTY_PROBE = /^(?:__system_property_(?:get|find|read|read_callback)|getprop)$/;
const STRING_CHECK = /^(?:strstr|strcasestr|strcmp|strncmp|strcasecmp|strncasecmp|memcmp|memmem)$/;

/** One combined score per detector, not a new confidence contribution for every
 * duplicate string/xref. A marker alone is a lead; a local API corroborates it.
 * This is co-occurrence evidence, not argument dataflow or proof of enforcement. */
function probe(id: string, label: string, marker: RegExp, apis: RegExp): Rule {
  return { id, description: `Referenced ${label} markers with function-local probe APIs`, run(ctx) {
    const strings = markers(ctx, marker);
    if (!strings.length) return [];
    const calls = called(ctx, apis);
    const weight = calls.length ? 0.72 : 0.32;
    return [{ label, weight, evidence: { address: strings[0].addr, certainty: "inference", text: `${calls.length ? "Corroborated candidate" : "String-only lead"}: references "${strings[0].value.slice(0, 100)}"${calls.length ? ` and calls ${calls.slice(0, 3).join(", ")} in this function` : "; no matching probe API resolved here"}. Co-occurrence does not establish how the value is used.` } }];
  } };
}
function apiRule(id: string, label: string, pattern: RegExp, description: string): Rule {
  return { id, description, run(ctx) {
    const calls = called(ctx, pattern);
    if (!calls.length) return [];
    return [{ label, weight: 0.65, evidence: { address: ctx.addr, certainty: "fact", text: `Calls ${calls.slice(0, 4).join(", ")}. ${description}` } }];
  } };
}

const ROOT_MARKER = /(?:\/(?:system\/(?:xbin|bin)|sbin|su\/bin|data\/local(?:\/xbin|\/bin)?)\/su(?:$|[\s"'])|\/data\/adb\/(?:magisk|ksu|ap)(?:\b|\/)|\b(?:magisk|kernelsu|apatch|supersu|superuser\.apk)\b|(?:^|\/)com\.(?:topjohnwu\.magisk|noshufou\.android\.su|koushikdutta\.superuser)(?:$|\b))/i;
const EMULATOR_MARKER = /(?:\bro\.(?:kernel|boot)\.qemu\b|\/dev\/(?:qemu_pipe|socket\/qemud)\b|\b(?:goldfish|ranchu|qemu|genymotion|vbox|virtualbox|sdk_gphone\w*|google_sdk|bluestacks|ldplayer|gameloop|noxplayer|mumu|memu)\b|\b(?:isEmulator|checkEmulator|detectEmulator)\b)/i;
const INSTRUMENTATION_MARKER = /(?:\b(?:frida(?:-agent|-gadget|-server)?|gum-js-loop|linjector|xposed|lsposed|substrate|riru|zygisk)\b|de\/robv\/android\/xposed\/|lib(?:frida|substrate|xposed))/i;

export const securityRules: Rule[] = [
  probe("security.debugger", "debugger-detection", /\b(?:TracerPid|isDebuggerConnected|waitingForDebugger)\b|debugger[ _-]detected/i, /^(?:ptrace|prctl|fopen(?:64)?|open(?:at|64)?|read|fgets|strstr|sscanf|strtol|atoi)$/),
  probe("security.root", "root-detection", ROOT_MARKER, new RegExp(`${FILE_PROBE.source}|${STRING_CHECK.source}`)),
  probe("security.emulator", "emulator-detection", EMULATOR_MARKER, new RegExp(`${FILE_PROBE.source}|${PROPERTY_PROBE.source}|${STRING_CHECK.source}`)),
  probe("security.instrumentation", "instrumentation-detection", INSTRUMENTATION_MARKER, new RegExp(`${FILE_PROBE.source}|${STRING_CHECK.source}|^(?:dl_iterate_phdr|dladdr|dlsym|connect)$`)),
  probe("security.proc", "process-inspection", /\/proc\/(?:self|thread-self|\d+|%[du])\/(?:maps|smaps|status|mem|task|fd|mountinfo|net\/tcp)(?:\b|\/)/i, FILE_PROBE),
  apiRule("security.tls", "tls-verification", /^(?:SSL(?:_CTX)?_set_(?:verify|cert_verify_callback|custom_verify)|SSL_get_verify_result|SSL_set1_host|X509_verify_cert|X509_check_host|mbedtls_ssl_(?:conf_authmode|get_verify_result)|mbedtls_x509_crt_verify(?:_with_profile)?)$/, "Touches TLS/certificate verification; the call alone does not prove verification is enabled or checked correctly."),
  probe("security.pinning", "certificate-pinning", /\b(?:certificate[ _-]?pinn?ing|public[ _-]?key[ _-]?pinn?ing|pinned[ _-]?(?:certificate|public[ _-]?key)|pin[ _-]?verification|CURLOPT_PINNEDPUBLICKEY)\b|sha256\/[A-Za-z0-9+/]{43}=/i, /^(?:SSL_get(?:1)?_peer_certificate|X509_(?:get_pubkey|digest)|EVP_(?:Digest|DigestFinal_ex|sha256)|CRYPTO_memcmp|memcmp|strcmp|curl_easy_setopt)$/),
  apiRule("security.signature", "signature-verification", /^(?:EVP_(?:DigestVerify(?:Init|Init_ex|Update|Final)?|PKEY_verify(?:_init)?|VerifyFinal)|RSA_verify|DSA_verify|ECDSA_(?:verify|do_verify)|crypto_sign_verify_detached|mbedtls_(?:pk_verify(?:_ext)?|rsa_pkcs1_verify|ecdsa_read_signature))$/, "Uses a digital-signature verification API; success handling still needs inspection."),
  apiRule("security.permissions", "memory-permission-change", /^(?:mprotect|pkey_mprotect|VirtualProtect(?:Ex)?)$/, "Changes memory page permissions. Execute permission and code modification are not inferred without argument dataflow."),
  apiRule("security.random", "secure-random", /^(?:getrandom|getentropy|arc4random(?:_buf|_uniform)?|RAND_(?:bytes|priv_bytes|bytes_ex|priv_bytes_ex)|randombytes_buf|BCryptGenRandom)$/ , "Uses an operating-system or cryptographic random source; return-value handling is not established."),
  apiRule("security.jni", "native-registration", /^(?:RegisterNatives|UnregisterNatives|_ZN7_JNIEnv(?:15RegisterNatives|17UnregisterNatives)E.*)$/, "Registers or unregisters native methods. Indirect JNI-table calls need separate resolution."),
  apiRule("security.erasure", "secure-erasure", /^(?:explicit_bzero|explicit_memset|memset_s|sodium_memzero|OPENSSL_cleanse|SecureZeroMemory|RtlSecureZeroMemory)$/, "Uses a dedicated memory-clearing API; the contents and complete lifetime of the buffer are not established."),
];
