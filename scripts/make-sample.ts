import { writeFileSync, mkdirSync } from "node:fs";
import { buildSampleSo } from "../tests/fixtures/elfBuilder";
mkdirSync("public/samples", { recursive: true });
writeFileSync("public/samples/libsample.so", buildSampleSo().bytes);
console.log("wrote public/samples/libsample.so");
