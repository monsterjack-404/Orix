// Bounded Android binary XML (AXML) metadata decoder. No XML entity expansion or external access.
import { OrixError } from '../core/errors.mjs';

const UTF8 = 0x00000100;
const TYPE_STRING_POOL = 0x0001;
const TYPE_RESOURCE_MAP = 0x0180;
const TYPE_START_NAMESPACE = 0x0100;
const TYPE_END_NAMESPACE = 0x0101;
const TYPE_START_ELEMENT = 0x0102;
const TYPE_END_ELEMENT = 0x0103;
const TYPE_CDATA = 0x0104;
const NO_INDEX = 0xffffffff;
const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}
function need(buffer, offset, size, end, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || size < 0 || offset < 0 || offset > end - size || end > buffer.length) {
    fail('ORIX_AXML_RANGE', 'Android binary XML ' + label + ' exceeds its enclosing bounds', { offset, size, end });
  }
}
function u16(b, o, end, label) { need(b, o, 2, end, label); return b.readUInt16LE(o); }
function u32(b, o, end, label) { need(b, o, 4, end, label); return b.readUInt32LE(o); }
function length8(b, offset, end) {
  need(b, offset, 1, end, 'UTF-8 string length');
  const first = b[offset++];
  if (first & 0x80) return { length: ((first & 0x7f) << 8) | u16(b, offset, end, 'UTF-8 string length'), next: offset + 2 };
  return { length: first, next: offset };
}
function length16(b, offset, end) {
  const first = u16(b, offset, end, 'UTF-16 string length'); offset += 2;
  if (first & 0x8000) return { length: ((first & 0x7fff) << 16) | u16(b, offset, end, 'UTF-16 string length'), next: offset + 2 };
  return { length: first, next: offset };
}
function decodeStringPool(b, start, headerSize, size, limits) {
  const end = start + size;
  if (headerSize < 28 || size < headerSize) fail('ORIX_AXML_STRING_POOL_HEADER', 'Invalid Android string-pool header');
  const count = u32(b, start + 8, end, 'string count');
  const styleCount = u32(b, start + 12, end, 'style count');
  const flags = u32(b, start + 16, end, 'string flags');
  const stringsStart = u32(b, start + 20, end, 'strings start');
  const stylesStart = u32(b, start + 24, end, 'styles start');
  if (count > limits.max_strings || styleCount > limits.max_strings || count + styleCount > limits.max_strings ||
      stringsStart < headerSize + 4 * (count + styleCount) || stringsStart > size ||
      (stylesStart !== 0 && (stylesStart < stringsStart || stylesStart > size))) {
    fail('ORIX_AXML_STRING_POOL_LIMIT', 'String-pool offsets or counts exceed configured bounds', { count, styleCount, stringsStart, stylesStart });
  }
  const offsetsStart = start + headerSize;
  const stringsBase = start + stringsStart;
  const stringsEnd = start + (stylesStart || size);
  need(b, offsetsStart, 4 * (count + styleCount), stringsBase, 'string offsets');
  const utf8 = (flags & UTF8) !== 0;
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const strings = [];
  for (let i = 0; i < count; i++) {
    const relative = u32(b, offsetsStart + i * 4, stringsBase, 'string offset');
    let cursor = stringsBase + relative;
    if (cursor < stringsBase || cursor >= stringsEnd) fail('ORIX_AXML_STRING_OFFSET', 'String offset is outside string data', { index: i, relative });
    let value;
    if (utf8) {
      const chars = length8(b, cursor, stringsEnd); cursor = chars.next;
      const bytes = length8(b, cursor, stringsEnd); cursor = bytes.next;
      need(b, cursor, bytes.length + 1, stringsEnd, 'UTF-8 string bytes');
      value = decoder.decode(b.subarray(cursor, cursor + bytes.length));
    } else {
      const chars = length16(b, cursor, stringsEnd); cursor = chars.next;
      const byteLength = chars.length * 2;
      need(b, cursor, byteLength + 2, stringsEnd, 'UTF-16 string bytes');
      value = b.toString('utf16le', cursor, cursor + byteLength);
    }
    strings.push(value);
  }
  return strings;
}
function stringAt(strings, index, label) {
  if (index === NO_INDEX) return null;
  if (index >= strings.length) fail('ORIX_AXML_STRING_INDEX', 'Invalid string-pool index for ' + label, { index, count: strings.length });
  return strings[index];
}
function typedValue(type, data, raw, strings) {
  if (raw !== null) return raw;
  if (type === 0x03) return stringAt(strings, data, 'typed string value');
  if (type === 0x10) return data | 0;
  if (type === 0x11) return '0x' + data.toString(16);
  if (type === 0x12) return data !== 0;
  if (type === 0x01) return '@0x' + data.toString(16);
  if (type === 0x02) return '?0x' + data.toString(16);
  if (type === 0x04) { const b = Buffer.alloc(4); b.writeUInt32LE(data); return b.readFloatLE(0); }
  return { type: '0x' + type.toString(16).padStart(2, '0'), data };
}
function qname(ns, name, namespaces) {
  if (!ns) return name;
  const bindings = namespaces.get(ns);
  const prefix = Array.isArray(bindings) ? bindings.at(-1) : bindings;
  return prefix ? prefix + ':' + name : name;
}

/** Parse bounded Android binary XML. Returns metadata candidates, not a semantic Android manifest verdict. */
export function parse_android_binary_xml(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Android binary XML input must be a Buffer');
  const limits = {
    max_file_bytes: options.max_file_bytes ?? 16 * 1024 * 1024,
    max_chunks: options.max_chunks ?? 100_000,
    max_strings: options.max_strings ?? 100_000,
    max_elements: options.max_elements ?? 20_000,
    max_attributes: options.max_attributes ?? 100_000,
    max_output_items: options.max_output_items ?? 10_000,
  };
  for (const [key, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > (key === 'max_file_bytes' ? 64 * 1024 * 1024 : 1_000_000)) {
      throw new TypeError(key + ' must be a positive bounded integer');
    }
  }
  if (buffer.length > limits.max_file_bytes) fail('ORIX_AXML_FILE_LIMIT', 'Android binary XML exceeds configured size limit', { size: buffer.length, limit: limits.max_file_bytes });
  if (buffer.length < 8 || u16(buffer, 0, buffer.length, 'root type') !== 0x0003) fail('ORIX_AXML_BAD_ROOT', 'Input is not an Android binary XML document');
  const rootHeader = u16(buffer, 2, buffer.length, 'root header size');
  const rootSize = u32(buffer, 4, buffer.length, 'root size');
  if (rootHeader !== 8 || rootSize < rootHeader || rootSize !== buffer.length) fail('ORIX_AXML_ROOT_RANGE', 'Invalid Android binary XML root size or trailing bytes');
  const strings = [];
  const namespaces = new Map();
  const namespaceStack = [];
  const stack = [];
  let stringPoolSeen = false;
  let resourceMapSeen = false;
  let manifestSeen = false;
  let manifestEnded = false;
  const permissions = [];
  const components = [];
  let packageName = null;
  let versionCode = null;
  let versionName = null;
  let application = null;
  let resourceMapCount = 0;
  let chunks = 0, elements = 0, attributesSeen = 0, outputTruncated = false;
  let cursor = rootHeader;
  const rootEnd = rootSize;
  while (cursor < rootEnd) {
    if (++chunks > limits.max_chunks) fail('ORIX_AXML_CHUNK_LIMIT', 'Android binary XML chunk limit exceeded');
    need(buffer, cursor, 8, rootEnd, 'chunk header');
    const type = u16(buffer, cursor, rootEnd, 'chunk type');
    const headerSize = u16(buffer, cursor + 2, rootEnd, 'chunk header size');
    const size = u32(buffer, cursor + 4, rootEnd, 'chunk size');
    if (headerSize < 8 || size < headerSize || size > rootEnd - cursor) fail('ORIX_AXML_CHUNK_RANGE', 'Invalid Android binary XML chunk framing', { type, cursor, headerSize, size });
    const end = cursor + size;
    if (type === TYPE_STRING_POOL) {
      if (stringPoolSeen) fail('ORIX_AXML_DUPLICATE_STRING_POOL', 'Multiple string pools are unsupported');
      stringPoolSeen = true;
      strings.push(...decodeStringPool(buffer, cursor, headerSize, size, limits));
    } else if (type === TYPE_RESOURCE_MAP) {
      if (!stringPoolSeen || resourceMapSeen) fail('ORIX_AXML_RESOURCE_MAP_ORDER', 'Android resource map must follow exactly one string pool');
      if ((size - headerSize) % 4 !== 0) fail('ORIX_AXML_RESOURCE_MAP', 'Invalid resource map size');
      resourceMapCount = (size - headerSize) / 4;
      if (resourceMapCount > strings.length) fail('ORIX_AXML_RESOURCE_MAP_RANGE', 'Resource map contains more IDs than string-pool entries');
      resourceMapSeen = true;
    } else if (type === TYPE_START_NAMESPACE || type === TYPE_END_NAMESPACE) {
      need(buffer, cursor + 16, 8, end, 'namespace extension');
      const prefix = stringAt(strings, u32(buffer, cursor + 16, end, 'namespace prefix'), 'namespace prefix');
      const uri = stringAt(strings, u32(buffer, cursor + 20, end, 'namespace URI'), 'namespace URI');
      if (!uri) fail('ORIX_AXML_NAMESPACE_URI', 'Namespace chunk requires a URI');
      if (type === TYPE_START_NAMESPACE) {
        namespaceStack.push({ prefix, uri });
        const bindings = namespaces.get(uri) ?? [];
        bindings.push(prefix ?? '');
        namespaces.set(uri, bindings);
      } else {
        const opened = namespaceStack.pop();
        if (!opened || opened.prefix !== prefix || opened.uri !== uri) fail('ORIX_AXML_NAMESPACE_MISMATCH', 'Namespace end chunk does not match the active namespace');
        const bindings = namespaces.get(uri);
        if (bindings?.length) bindings.pop();
        if (!bindings?.length) namespaces.delete(uri);
      }
    } else if (type === TYPE_START_ELEMENT) {
      if (++elements > limits.max_elements) fail('ORIX_AXML_ELEMENT_LIMIT', 'Android binary XML element limit exceeded');
      need(buffer, cursor + 16, 20, end, 'element extension');
      const ns = stringAt(strings, u32(buffer, cursor + 16, end, 'element namespace'), 'element namespace');
      const name = stringAt(strings, u32(buffer, cursor + 20, end, 'element name'), 'element name');
      const attributeStart = u16(buffer, cursor + 24, end, 'attribute start');
      const attributeSize = u16(buffer, cursor + 26, end, 'attribute size');
      const attributeCount = u16(buffer, cursor + 28, end, 'attribute count');
      if (!name || attributeSize < 20 || attributeCount > limits.max_attributes - attributesSeen) fail('ORIX_AXML_ATTRIBUTE_LIMIT', 'Invalid or excessive Android XML attributes');
      if (attributeStart < 20) fail('ORIX_AXML_ATTRIBUTE_START', 'Attribute array must begin after the complete attribute extension');
      const attributesOffset = cursor + 16 + attributeStart;
      need(buffer, attributesOffset, attributeCount * attributeSize, end, 'attribute array');
      // Avoid the legacy __proto__ setter for untrusted manifest attribute names.
      const attrs = Object.create(null);
      for (let i = 0; i < attributeCount; i++) {
        const at = attributesOffset + i * attributeSize;
        const ans = stringAt(strings, u32(buffer, at, end, 'attribute namespace'), 'attribute namespace');
        const aname = stringAt(strings, u32(buffer, at + 4, end, 'attribute name'), 'attribute name');
        const rawIndex = u32(buffer, at + 8, end, 'attribute raw value');
        const valueSize = u16(buffer, at + 12, end, 'typed value size');
        const valueType = buffer[at + 15];
        const valueData = u32(buffer, at + 16, end, 'typed value data');
        if (!aname || valueSize < 8) fail('ORIX_AXML_ATTRIBUTE_VALUE', 'Invalid Android XML attribute value');
        const raw = stringAt(strings, rawIndex, 'raw attribute value');
        const qualifiedName = ans === ANDROID_NS ? 'android:' + aname : qname(ans, aname, namespaces);
        if (Object.hasOwn(attrs, qualifiedName)) fail('ORIX_AXML_DUPLICATE_ATTRIBUTE', 'Duplicate Android XML attribute name', { name: qualifiedName });
        attrs[qualifiedName] = typedValue(valueType, valueData, raw, strings);
        attributesSeen++;
      }
      const tag = qname(ns, name, namespaces);
      if (stack.length === 0) {
        if (manifestSeen || name !== 'manifest' || ns !== null) fail('ORIX_AXML_ROOT_ELEMENT', 'Android manifest must contain exactly one unqualified manifest root element');
        manifestSeen = true;
      }
      const frame = { tag, ns, name, attrs };
      stack.push(frame);
      if (tag === 'manifest') {
        packageName = attrs.package ?? null;
        versionCode = attrs['android:versionCode'] ?? null;
        versionName = attrs['android:versionName'] ?? null;
      } else if (tag === 'uses-permission' || tag === 'uses-permission-sdk-23' || tag === 'uses-permission-sdk-m') {
        const permission = attrs['android:name'] ?? attrs.name;
        if (permission && permissions.length < limits.max_output_items) permissions.push({ name: permission, maxSdkVersion: attrs['android:maxSdkVersion'] ?? null });
        else if (permission) outputTruncated = true;
      } else if (['activity','activity-alias','service','receiver','provider'].includes(tag)) {
        if (components.length < limits.max_output_items) components.push({
          type: tag, name: attrs['android:name'] ?? attrs.name ?? null,
          exported: attrs['android:exported'] ?? null,
          permission: attrs['android:permission'] ?? null,
          process: attrs['android:process'] ?? null,
          authorities: attrs['android:authorities'] ?? null,
          targetActivity: attrs['android:targetActivity'] ?? null,
        });
        else outputTruncated = true;
      } else if (tag === 'application') {
        application = {
          label: attrs['android:label'] ?? null,
          icon: attrs['android:icon'] ?? null,
          debuggable: attrs['android:debuggable'] ?? null,
          allowBackup: attrs['android:allowBackup'] ?? null,
          usesCleartextTraffic: attrs['android:usesCleartextTraffic'] ?? null,
          networkSecurityConfig: attrs['android:networkSecurityConfig'] ?? null,
        };
      }
    } else if (type === TYPE_END_ELEMENT) {
      need(buffer, cursor + 16, 8, end, 'end-element extension');
      const ns = stringAt(strings, u32(buffer, cursor + 16, end, 'end-element namespace'), 'end-element namespace');
      const name = stringAt(strings, u32(buffer, cursor + 20, end, 'end-element name'), 'end-element name');
      const opened = stack.pop();
      if (!opened || opened.ns !== ns || opened.name !== name) fail('ORIX_AXML_MISMATCHED_END_TAG', 'Android XML end element does not match its opening element', { name });
      if (stack.length === 0) manifestEnded = true;
    } else if (type === TYPE_CDATA) {
      need(buffer, cursor + 16, 12, end, 'CDATA extension');
      if (stringAt(strings, u32(buffer, cursor + 16, end, 'CDATA string'), 'CDATA string') === null) {
        fail('ORIX_AXML_CDATA_INDEX', 'CDATA chunk is missing its text string');
      }
    }
    cursor = end;
  }
  if (cursor !== rootEnd || stack.length !== 0 || namespaceStack.length !== 0 || !stringPoolSeen || !manifestSeen || !manifestEnded) fail('ORIX_AXML_STRUCTURE', 'Android binary XML ended with incomplete structure');
  return {
    decoded: true, package_name: packageName, version_code: versionCode, version_name: versionName,
    permissions, components, application, counts: { chunks, strings: strings.length, elements, attributes: attributesSeen, resource_map_entries: resourceMapCount },
    output_truncated: outputTruncated,
    notes: ['Android resource references are preserved as numeric identifiers; resource table resolution is not performed.', 'Component exported state is reported only when explicitly encoded; target SDK default rules are not inferred.'],
  };
}
