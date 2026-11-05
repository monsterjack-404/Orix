// JavaScript, src/formats/ubifs-master.mjs, Node.js 20+, bounded read-only UBIFS master-node analysis.
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const HEADER = 24, SIZE = 512, MAGIC = 0x06101831, TYPE = 7, MAX_INPUT = 64 * 1024 * 1024;
const FLAGS = Object.freeze([[1, 'dirty'], [2, 'no_orphans'], [4, 'recovery']]);
function reject(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}
function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return crc >>> 0;
}
function safe(value, field) {
  if (typeof value === 'string' || !Number.isSafeInteger(value)) {
    reject('ORIX_UBIFS_MASTER_UNSAFE_INTEGER', 'UBIFS master ' + field + ' exceeds the safe integer range', { field, value: String(value) });
  }
  return value;
}

/** Parse one UBIFS master node. options.superblock optionally supplies parse_ubifs() output for geometry cross-checks. */
export function parse_ubifs_master(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_ubifs_master requires a Buffer');
  const limit = options.max_input_bytes ?? MAX_INPUT, offset = options.offset ?? 0;
  if (!Number.isSafeInteger(limit) || limit < SIZE || limit > MAX_INPUT) throw new TypeError('max_input_bytes must be an integer between 512 and ' + MAX_INPUT);
  if (buffer.length > limit) reject('ORIX_UBIFS_MASTER_INPUT_LIMIT', 'UBIFS master input exceeds the configured byte limit', { size: buffer.length, limit });
  if (!Number.isSafeInteger(offset) || offset < 0 || offset % 8 !== 0 || offset + SIZE > buffer.length) {
    reject('ORIX_UBIFS_MASTER_TRUNCATED', 'UBIFS master node must fit at an 8-byte-aligned offset', { offset, available: buffer.length });
  }
  const r = new BinaryReader(buffer, { label: 'UBIFS master node' });
  if (r.u32(offset, true, 'node magic') !== MAGIC) reject('ORIX_UBIFS_MASTER_BAD_MAGIC', 'UBIFS node magic is not present at the selected offset', { offset });
  const stored_crc = r.u32(offset + 4, true, 'node CRC');
  const sequence_number = r.u64(offset + 8, true, 'node sequence number');
  const node_length = r.u32(offset + 16, true, 'node length');
  const node_type = r.u8(offset + 20, 'node type');
  const group_type = r.u8(offset + 21, 'node group type');
  const common_padding = r.bytes(offset + 22, 2, 'common padding');
  if (node_type !== TYPE) reject('ORIX_UBIFS_MASTER_WRONG_TYPE', 'UBIFS node is not a master node', { node_type, expected: TYPE });
  if (group_type > 2) reject('ORIX_UBIFS_MASTER_GROUP_TYPE', 'UBIFS master group type is invalid', { group_type });
  if (common_padding.some(x => x !== 0)) reject('ORIX_UBIFS_MASTER_COMMON_PADDING', 'UBIFS master common padding must be zero');
  if (node_length !== SIZE) reject('ORIX_UBIFS_MASTER_INVALID_LENGTH', 'UBIFS master node must be exactly 512 bytes', { node_length, expected: SIZE });
  if (offset + node_length > buffer.length) reject('ORIX_UBIFS_MASTER_TRUNCATED', 'UBIFS master node extends beyond input', { offset, node_length });
  const calculated_crc = crc32(buffer.subarray(offset + 8, offset + node_length));
  if (stored_crc !== calculated_crc) reject('ORIX_UBIFS_MASTER_CRC_MISMATCH', 'UBIFS master node CRC does not match', { stored_crc, calculated_crc });

  const b = offset + HEADER;
  const u32 = (n, name) => r.u32(b + n, true, name);
  const u64 = (n, name) => r.u64(b + n, true, name);
  const has = (n, len, name) => r.bytes(b + n, len, name).some(x => x !== 0);
  const highest_inode_number = String(u64(0, 'highest inode number'));
  const commit_number = String(u64(8, 'commit number'));
  const flags_value = u32(16, 'master flags');
  const log_lnum = u32(20, 'log LEB number');
  const root_lnum = u32(24, 'root LEB number');
  const root_offs = u32(28, 'root index offset');
  const root_len = u32(32, 'root index length');
  const gc_raw = u32(36, 'GC LEB number');
  const ihead_lnum = u32(40, 'index-head LEB number');
  const ihead_offs = u32(44, 'index-head offset');
  const index_size = safe(u64(48, 'index size'), 'index size');
  const total_free = safe(u64(56, 'total free'), 'total free');
  const total_dirty = safe(u64(64, 'total dirty'), 'total dirty');
  const total_used = safe(u64(72, 'total used'), 'total used');
  const total_dead = safe(u64(80, 'total dead'), 'total dead');
  const total_dark = safe(u64(88, 'total dark'), 'total dark');
  const lpt_lnum = u32(96, 'LPT root LEB');
  const lpt_offs = u32(100, 'LPT root offset');
  const nhead_lnum = u32(104, 'LPT head LEB');
  const nhead_offs = u32(108, 'LPT head offset');
  const ltab_lnum = u32(112, 'LPT table LEB');
  const ltab_offs = u32(116, 'LPT table offset');
  const lsave_lnum = u32(120, 'LPT save LEB');
  const lsave_offs = u32(124, 'LPT save offset');
  const lscan_lnum = u32(128, 'last LPT scan LEB');
  const empty_lebs = u32(132, 'empty LEB count');
  const index_lebs = u32(136, 'index LEB count');
  const leb_count = u32(140, 'master LEB count');
  const root_index_hash_present = has(144, 64, 'root index hash');
  const lpt_hash_present = has(208, 64, 'LPT hash');
  const hmac_present = has(272, 64, 'master HMAC');
  const padding = r.bytes(b + 336, 152, 'master reserved padding');

  if (padding.some(x => x !== 0)) reject('ORIX_UBIFS_MASTER_PADDING', 'UBIFS master reserved padding must be zero');
  if (BigInt(commit_number) >= BigInt(String(sequence_number))) reject('ORIX_UBIFS_MASTER_COMMIT_SEQUENCE', 'Master commit number must be below node sequence number', { commit_number, sequence_number: String(sequence_number) });
  if (BigInt(highest_inode_number) >= 0x7fffffffn) reject('ORIX_UBIFS_MASTER_INODE_WATERMARK', 'Highest inode number exceeds UBIFS watermark', { highest_inode_number });
  if (leb_count < 20 || index_size % 8 || root_offs % 8 || ihead_offs % 8 || root_len < 28) {
    reject('ORIX_UBIFS_MASTER_LAYOUT', 'Master LEB count, root-index length or index alignment is invalid', { leb_count, index_size, root_offs, ihead_offs, root_len });
  }
  for (const [field, value] of Object.entries({ total_free, total_dirty, total_used, total_dead, total_dark })) {
    if (value % 8) reject('ORIX_UBIFS_MASTER_COUNTER_ALIGNMENT', 'Master space counters must be 8-byte aligned', { field, value });
  }

  const gc_lnum = gc_raw === 0xffffffff ? null : gc_raw;
  if (log_lnum >= leb_count || root_lnum >= leb_count || (gc_lnum !== null && gc_lnum >= leb_count) || ihead_lnum >= leb_count || lscan_lnum >= leb_count) {
    reject('ORIX_UBIFS_MASTER_LEB_BOUNDS', 'Master node contains a LEB reference outside its own declared LEB count', { log_lnum, root_lnum, gc_lnum, ihead_lnum, lscan_lnum, leb_count });
  }
  const geometry = options.superblock?.superblock ?? options.superblock ?? null;
  let geometry_validated = false;
  if (geometry !== null) {
    const required = ['leb_size', 'max_leb_count', 'log_lebs', 'lpt_lebs', 'orphan_lebs', 'min_io_size'];
    if (!required.every(k => Number.isSafeInteger(geometry[k]) && geometry[k] > 0)) throw new TypeError('superblock must be parse_ubifs() output or a geometry object');
    const main_first = 3 + geometry.log_lebs + geometry.lpt_lebs + geometry.orphan_lebs;
    const lpt_first = 3 + geometry.log_lebs, lpt_last = lpt_first + geometry.lpt_lebs - 1;
    const main_lebs = leb_count - main_first, main_bytes = main_lebs * geometry.leb_size;
    const inMain = n => n >= main_first && n < leb_count;
    const inLpt = n => n >= lpt_first && n <= lpt_last;
    if (leb_count > geometry.max_leb_count || main_lebs < 9) reject('ORIX_UBIFS_MASTER_LEB_COUNT', 'Master LEB count exceeds superblock capacity or leaves too few main LEBs', { leb_count, max_leb_count: geometry.max_leb_count, main_lebs });
    if (log_lnum < 3 || log_lnum >= 3 + geometry.log_lebs || !inMain(root_lnum) ||
        (gc_lnum !== null && !inMain(gc_lnum)) || !inMain(ihead_lnum) || !inMain(lscan_lnum)) {
      reject('ORIX_UBIFS_MASTER_LEB_RANGE', 'Master journal or main-area LEB references exceed superblock layout', { log_lnum, root_lnum, gc_lnum, ihead_lnum, lscan_lnum, main_first, leb_count });
    }
    if (root_offs >= geometry.leb_size || root_len > geometry.leb_size ||
        ihead_offs > geometry.leb_size || ihead_offs % geometry.min_io_size ||
        !inLpt(lpt_lnum) || !inLpt(nhead_lnum) || !inLpt(ltab_lnum) ||
        lpt_offs >= geometry.leb_size || nhead_offs > geometry.leb_size || ltab_offs >= geometry.leb_size) {
      reject('ORIX_UBIFS_MASTER_OFFSET_RANGE', 'Master offsets or LPT references exceed superblock geometry', { root_offs, root_len, ihead_offs, lpt_lnum, lpt_offs, nhead_lnum, nhead_offs, ltab_lnum, ltab_offs, leb_size: geometry.leb_size });
    }
    const superblock_flags = typeof geometry.flags === 'number' ? geometry.flags : (geometry.flags?.value ?? 0);
    if ((superblock_flags & 2) && (!inLpt(lsave_lnum) || lsave_offs > geometry.leb_size)) reject('ORIX_UBIFS_MASTER_LSAVE_RANGE', 'Big-LPT save-table reference exceeds LPT geometry', { lsave_lnum, lsave_offs });
    if (total_free + total_dirty + total_used > main_bytes || total_dead > total_free + total_dirty ||
        total_dark > total_free + total_dirty || empty_lebs > main_lebs - 2 || index_lebs > main_lebs - 1 ||
        total_dead + total_dark + total_used + index_size > main_bytes) {
      reject('ORIX_UBIFS_MASTER_SPACE_RANGE', 'Master space counters exceed main-area geometry', { total_free, total_dirty, total_used, total_dead, total_dark, empty_lebs, index_lebs, index_size, main_bytes, main_lebs });
    }
    geometry_validated = true;
  }
  const known_flags = FLAGS.reduce((m, [bit]) => m | bit, 0);
  const enabled_flags = FLAGS.filter(([bit]) => flags_value & bit).map(([, name]) => name);
  return {
    format: 'UBIFS', variant: 'master-node', analysis_scope: 'single-master-node-metadata-only',
    node: { magic: '0x06101831', offset, length: node_length, type: TYPE, type_name: 'master', group_type, sequence_number: String(sequence_number), stored_crc, calculated_crc, crc_valid: true },
    master: {
      highest_inode_number, commit_number,
      flags: { value: flags_value, enabled: enabled_flags, unknown_bits: (flags_value & ~known_flags) >>> 0 },
      log_lnum, root_lnum, root_offs, root_len, gc_lnum, ihead_lnum, ihead_offs, index_size,
      total_free, total_dirty, total_used, total_dead, total_dark,
      lpt_lnum, lpt_offs, nhead_lnum, nhead_offs, ltab_lnum, ltab_offs, lsave_lnum, lsave_offs,
      lscan_lnum, empty_lebs, index_lebs, leb_count,
      hashes: { root_index_present: root_index_hash_present, lpt_present: lpt_hash_present },
      authentication: { hmac_present },
    },
    validation: {
      common_header_valid: true, master_node_type_valid: true, node_length_valid: true, node_crc_valid: true,
      reserved_padding_zero: true, commit_number_below_sequence_number: true, basic_master_layout_valid: true,
      superblock_geometry_validated: geometry_validated, hmac_verified: false, hashes_verified: false, index_tree_traversed: false,
    },
    limitations: [
      'Only one UBIFS master node is decoded; duplicate-master consistency and recovery selection are not performed.',
      'Master HMAC and embedded hashes are inventoried but not cryptographically verified.',
      'No index tree, journal, LPT contents, orphan records, inode/directory/data nodes or file payloads are traversed.',
      'A valid node CRC and plausible master metadata do not establish filesystem-wide integrity or authenticity.',
    ],
  };
}
