// JavaScript, src/core/inspect.mjs, Node.js 20+, read-only artifact inspection.
import { createReadStream } from "node:fs";
import { lstat } from "node:fs/promises";
import { createHash } from "node:crypto";

const signatures = [
  ["ELF", [0x7f,0x45,0x4c,0x46]],
  ["PE/DOS executable marker", [0x4d,0x5a]],
  ["ZIP archive", [0x50,0x4b,0x03,0x04]],
  ["PDF document", [0x25,0x50,0x44,0x46]],
  ["PNG image", [0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]],
  ["JPEG image", [0xff,0xd8,0xff]],
  ["WebAssembly module", [0x00,0x61,0x73,0x6d]],
  ["GZIP archive", [0x1f,0x8b]],
  ["SQLite database", [0x53,0x51,0x4c,0x69,0x74,0x65,0x20,0x66,0x6f,0x72,0x6d,0x61,0x74,0x20,0x33,0x00]],
  ["Mach-O 32-bit", [0xce,0xfa,0xed,0xfe]],
  ["Mach-O 64-bit", [0xcf,0xfa,0xed,0xfe]]
];

function detectFormat(header) {
  const match = signatures.find((entry) => entry[1].every((byte, i) => header[i] === byte));
  return match ? match[0] : "Unknown";
}

export async function inspectArtifact(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0) throw new TypeError("filePath must be a non-empty string");
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Only regular files can be inspected");
  const hash = createHash("sha256");
  const previewChunks = [];
  let previewLength = 0;
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk);
    if (previewLength < 64) {
      const part = chunk.subarray(0, 64 - previewLength);
      previewChunks.push(part);
      previewLength += part.length;
    }
  }
  const preview = Buffer.concat(previewChunks);
  return {
    file: filePath,
    size: metadata.size,
    modifiedAt: metadata.mtime.toISOString(),
    sha256: hash.digest("hex"),
    format: detectFormat(preview),
    previewHex: preview.toString("hex").match(/.{1,2}/g)?.join(" ") ?? ""
  };
}
