// JavaScript, src/formats/macho.mjs, Node.js 20+, read-only Mach-O header and load-command parser.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MAGIC = new Map([
  ['feedface', { little: false, is_64: false }], ['cefaedfe', { little: true, is_64: false }],
  ['feedfacf', { little: false, is_64: true }], ['cffaedfe', { little: true, is_64: true }],
]);
const CPU = new Map([[7,'x86'],[0x01000007,'x86-64'],[12,'ARM'],[0x0100000c,'ARM64'],[18,'PowerPC'],[0x01000012,'PowerPC64']]);

export function parse_macho(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'Mach-O image' });
  const magic = buffer.subarray(0, 4).toString('hex');
  const spec = MAGIC.get(magic);
  if (!spec) throw new OrixError('ORIX_MACHO_BAD_MAGIC', 'Input does not contain a supported thin Mach-O header', { recoverable: true });
  const minimum = spec.is_64 ? 32 : 28;
  reader.require(0, minimum, 'Mach-O header');
  const cpu_type = reader.i32(4, spec.little, 'CPU type');
  const cpu_subtype = reader.i32(8, spec.little, 'CPU subtype');
  const file_type = reader.u32(12, spec.little, 'file type');
  const command_count = reader.u32(16, spec.little, 'load-command count');
  const command_bytes = reader.u32(20, spec.little, 'load-command byte count');
  const flags = reader.u32(24, spec.little, 'Mach-O flags');
  const maximum_commands = options.max_commands ?? 8_192;
  if (command_count > maximum_commands) throw new OrixError('ORIX_MACHO_COMMAND_LIMIT', 'Mach-O load-command count exceeds configured limit', { details: { command_count, maximum_commands }, recoverable: true });
  const command_offset = minimum;
  reader.require(command_offset, command_bytes, 'load-command region');
  const commands = [];
  let cursor = command_offset;
  for (let index = 0; index < command_count; index += 1) {
    reader.require(cursor, 8, `load command ${index}`);
    const command = reader.u32(cursor, spec.little, 'load-command ID');
    const size = reader.u32(cursor + 4, spec.little, 'load-command size');
    if (size < 8 || size > command_offset + command_bytes - cursor) {
      throw new OrixError('ORIX_MACHO_BAD_LOAD_COMMAND', 'Mach-O load command has an invalid size', { details: { index, command, size, cursor }, recoverable: true });
    }
    commands.push({ index, command: `0x${command.toString(16)}`, size });
    cursor += size;
  }
  return {
    format: 'Mach-O', bitness: spec.is_64 ? 64 : 32,
    endianness: spec.little ? 'little' : 'big', architecture: CPU.get(cpu_type) ?? `unknown-${cpu_type}`,
    header: { cpu_type, cpu_subtype, file_type, command_count, command_bytes, flags, reserved: spec.is_64 ? reader.u32(28, spec.little, 'reserved') : null },
    load_commands: commands,
    notes: ['Thin Mach-O headers are supported. Universal/fat containers are identified by the registry but not yet expanded.', 'Load-command payloads are bounded; command-specific structures are not decoded in this release.'],
  };
}
