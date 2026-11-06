// JavaScript, tests/fixtures/rizin-stub.mjs, deterministic cross-platform Rizin CLI contract fixture.
import { chmod, readFile, writeFile } from 'node:fs/promises';

const [config_path, ...args] = process.argv.slice(2);
const config = JSON.parse(await readFile(config_path, 'utf8'));
const write = value => new Promise(resolve => process.stdout.write(String(value), resolve));

if (args[0] === '-v') {
  await write(config.version_output ?? 'rizin 0.8.2 0 @ test-build');
  process.exit(config.version_exit_code ?? 0);
}

const command_index = args.indexOf('-c');
const command = command_index >= 0 ? args[command_index + 1] : null;

if (command === 'iij') {
  if (config.delay_import_ms) await new Promise(resolve => setTimeout(resolve, config.delay_import_ms));
  if (config.mutate_snapshot) {
    const snapshot_path = args.at(-1);
    await chmod(snapshot_path, 0o600);
    await writeFile(snapshot_path, 'provider-mutated-snapshot');
  }
  await write(config.import_output ?? JSON.stringify([
    { name: 'puts', libname: 'libc.so.6', ordinal: 1, bind: 'GLOBAL', type: 'FUNC', plt: 4096 },
    { name: 'custom', library: 'libdemo.so', ordinal: 2, bind: 'WEAK', type: 'FUNC', plt: '0x2000' },
  ]));
  process.exit(config.import_exit_code ?? 0);
}

if (command === 'axlj') {
  await write(config.references_output ?? '[]');
  process.exit(0);
}

if (command === 'aflj') {
  await write(config.function_output ?? JSON.stringify([
    { offset: 4198400, name: 'sym.main', size: 40, realsz: 40, bits: 64, type: 'fcn', calltype: 'amd64', nbbs: 3, edges: 2, nargs: 1, nlocals: 2, noreturn: false },
  ]));
  process.exit(0);
}

if (typeof command === 'string' && command.startsWith('pdj')) {
  await write(config.disassembly_output ?? JSON.stringify([
    { offset: 4198400, size: 5, bytes: '554889e5', opcode: 'push rbp', disasm: 'push rbp', type: 'push' },
    { offset: 4198401, size: 3, bytes: '4889e5', opcode: 'mov rbp, rsp', disasm: 'mov rbp, rsp', type: 'mov' },
    { offset: 4198404, size: 1, bytes: 'c3', opcode: 'ret', disasm: 'ret', type: 'ret' },
  ]));
  process.exit(0);
}

if (typeof command === 'string' && command.startsWith('pdg')) {
  await write(config.decompilation_output ?? 'int main(void) { return 0; }');
  process.exit(0);
}

process.stderr.write('Unsupported fixture command');
process.exit(64);
