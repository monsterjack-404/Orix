// JavaScript, tests/inspect.test.mjs, Node.js 20+, inspector unit tests.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { inspectArtifact } from "../src/core/inspect.mjs";

test("calculates SHA-256 and recognizes PNG", async () => {
  const dir = await mkdtemp(join(tmpdir(), "orix-"));
  try {
    const file = join(dir, "sample.png");
    const bytes = Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,1,2,3]);
    await writeFile(file, bytes);
    const result = await inspectArtifact(file);
    assert.equal(result.format, "PNG image");
    assert.equal(result.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.equal(result.size, bytes.length);
  } finally { await rm(dir, {recursive:true,force:true}); }
});

test("returns Unknown for unrecognized data", async () => {
  const dir = await mkdtemp(join(tmpdir(), "orix-"));
  try {
    const file = join(dir, "sample.bin");
    await writeFile(file, "ORIX test artifact");
    assert.equal((await inspectArtifact(file)).format, "Unknown");
  } finally { await rm(dir, {recursive:true,force:true}); }
});

test("rejects directories", async () => {
  const dir = await mkdtemp(join(tmpdir(), "orix-"));
  try { await assert.rejects(inspectArtifact(dir), /Only regular files/); }
  finally { await rm(dir, {recursive:true,force:true}); }
});

test("rejects symbolic links", async () => {
  const dir = await mkdtemp(join(tmpdir(), "orix-"));
  try {
    const target = join(dir, "target");
    const link = join(dir, "link");
    await writeFile(target, "data");
    await symlink(target, link);
    await assert.rejects(inspectArtifact(link));
  } finally { await rm(dir, {recursive:true,force:true}); }
});
