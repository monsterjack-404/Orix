// Bounded decoder for the AAPT2 Resources.XmlNode protobuf used by Android App Bundles.
// It parses manifest structure only. Resource-table references and BundleConfig semantics
// are intentionally not resolved here.
const ANDROID_NS = 'http://schemas.android.com/apk/res/android';
const COMPONENT_TYPES = new Set(['activity', 'activity-alias', 'service', 'receiver', 'provider']);

function fail(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  throw error;
}

function bounded_integer(name, value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(name + ' must be an integer between ' + minimum + ' and ' + maximum);
  }
  return value;
}

function read_varint(buffer, cursor, end, label) {
  let value = 0n;
  let shift = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (cursor >= end) fail('ORIX_PROTO_XML_VARINT_TRUNCATED', 'Truncated protobuf varint', { label, offset: cursor });
    const byte = buffer[cursor++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        fail('ORIX_PROTO_XML_VARINT_RANGE', 'Protobuf integer exceeds the safe numeric range', { label, offset: cursor });
      }
      return { value: Number(value), next: cursor };
    }
    shift += 7n;
  }
  fail('ORIX_PROTO_XML_VARINT_OVERFLOW', 'Protobuf varint is longer than ten bytes', { label, offset: cursor });
}

function read_length(buffer, cursor, end, label) {
  const decoded = read_varint(buffer, cursor, end, label + ' length');
  if (decoded.value > end - decoded.next) {
    fail('ORIX_PROTO_XML_LENGTH_RANGE', 'Protobuf field length exceeds its enclosing message', {
      label, offset: cursor, length: decoded.value, remaining: end - decoded.next,
    });
  }
  return { start: decoded.next, end: decoded.next + decoded.value, next: decoded.next + decoded.value };
}

function decode_utf8(buffer, start, end, label, budget, limits) {
  const size = end - start;
  if (size > limits.max_string_bytes || budget.string_bytes > limits.max_total_string_bytes - size) {
    fail('ORIX_PROTO_XML_STRING_LIMIT', 'Protobuf XML string budget exceeded', {
      label, size, max_string_bytes: limits.max_string_bytes,
      total: budget.string_bytes, max_total_string_bytes: limits.max_total_string_bytes,
    });
  }
  budget.string_bytes += size;
  budget.strings += 1;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(start, end));
  } catch {
    fail('ORIX_PROTO_XML_UTF8', 'Protobuf XML string is not valid UTF-8', { label, offset: start, size });
  }
}

function walk_fields(buffer, start, end, budget, visitor, label) {
  let cursor = start;
  while (cursor < end) {
    if (++budget.fields > budget.limits.max_fields) {
      fail('ORIX_PROTO_XML_FIELD_LIMIT', 'Protobuf XML field-count limit exceeded', {
        max_fields: budget.limits.max_fields,
      });
    }
    const tag = read_varint(buffer, cursor, end, label + ' tag');
    cursor = tag.next;
    const field_number = Math.floor(tag.value / 8);
    const wire_type = tag.value & 7;
    if (field_number < 1 || field_number > 0x1fffffff) {
      fail('ORIX_PROTO_XML_FIELD_NUMBER', 'Protobuf XML field number is invalid', { label, field_number });
    }
    let value;
    if (wire_type === 0) {
      const decoded = read_varint(buffer, cursor, end, label + ' scalar');
      value = decoded.value;
      cursor = decoded.next;
    } else if (wire_type === 1) {
      if (cursor > end - 8) fail('ORIX_PROTO_XML_FIXED64_RANGE', 'Truncated protobuf fixed64 field', { label, field_number, offset: cursor });
      value = { start: cursor, end: cursor + 8 };
      cursor += 8;
    } else if (wire_type === 2) {
      value = read_length(buffer, cursor, end, label + ' field ' + field_number);
      cursor = value.next;
    } else if (wire_type === 5) {
      if (cursor > end - 4) fail('ORIX_PROTO_XML_FIXED32_RANGE', 'Truncated protobuf fixed32 field', { label, field_number, offset: cursor });
      value = { start: cursor, end: cursor + 4 };
      cursor += 4;
    } else {
      fail('ORIX_PROTO_XML_WIRE_TYPE', 'Unsupported protobuf wire type', { label, field_number, wire_type });
    }
    visitor(field_number, wire_type, value);
  }
  if (cursor !== end) fail('ORIX_PROTO_XML_MESSAGE_RANGE', 'Protobuf XML message did not end at its declared boundary', { label, cursor, end });
}

function expect_wire(label, field, actual, expected) {
  if (actual !== expected) {
    fail('ORIX_PROTO_XML_WIRE_MISMATCH', 'Protobuf XML field has an unexpected wire type', {
      label, field, expected, actual,
    });
  }
}

function parse_namespace(buffer, start, end, budget, limits) {
  const result = { prefix: '', uri: '' };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 2) {
      expect_wire('XmlNamespace', field, wire, 2);
      if (seen.has(field)) fail('ORIX_PROTO_XML_DUPLICATE_FIELD', 'Duplicate XmlNamespace scalar field', { field });
      seen.add(field);
      result[field === 1 ? 'prefix' : 'uri'] = decode_utf8(buffer, value.start, value.end, 'XmlNamespace.' + field, budget, limits);
    }
    // SourcePosition (field 3) and future fields are safely skipped by wire type.
  }, 'XmlNamespace');
  if (!result.uri) fail('ORIX_PROTO_XML_NAMESPACE_URI', 'XmlNamespace requires a non-empty URI');
  return result;
}

function parse_attribute(buffer, start, end, budget, limits) {
  const result = { namespace_uri: '', name: '', value: '', resource_id: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field >= 1 && field <= 3) {
      expect_wire('XmlAttribute', field, wire, 2);
      if (seen.has(field)) fail('ORIX_PROTO_XML_DUPLICATE_FIELD', 'Duplicate XmlAttribute scalar field', { field });
      seen.add(field);
      const key = field === 1 ? 'namespace_uri' : field === 2 ? 'name' : 'value';
      result[key] = decode_utf8(buffer, value.start, value.end, 'XmlAttribute.' + key, budget, limits);
    } else if (field === 5) {
      expect_wire('XmlAttribute', field, wire, 0);
      if (seen.has(field)) fail('ORIX_PROTO_XML_DUPLICATE_FIELD', 'Duplicate XmlAttribute resource_id', { field });
      seen.add(field);
      if (value > 0xffffffff) fail('ORIX_PROTO_XML_RESOURCE_ID', 'XmlAttribute resource_id exceeds uint32');
      result.resource_id = value;
    }
    // SourcePosition (field 4), compiled Item (field 6) and future fields are skipped.
  }, 'XmlAttribute');
  if (!result.name) fail('ORIX_PROTO_XML_ATTRIBUTE_NAME', 'XmlAttribute requires a non-empty name');
  return result;
}

function parse_element(buffer, start, end, budget, limits, depth) {
  if (depth > limits.max_depth) {
    fail('ORIX_PROTO_XML_DEPTH_LIMIT', 'Protobuf XML nesting depth exceeds configured limit', { depth, max_depth: limits.max_depth });
  }
  if (++budget.elements > limits.max_elements) {
    fail('ORIX_PROTO_XML_ELEMENT_LIMIT', 'Protobuf XML element-count limit exceeded', { max_elements: limits.max_elements });
  }
  const result = { namespace_uri: '', name: '', namespaces: [], attributes: [], children: [] };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('XmlElement', field, wire, 2);
      if (++budget.namespaces > limits.max_namespaces) fail('ORIX_PROTO_XML_NAMESPACE_LIMIT', 'Protobuf XML namespace limit exceeded');
      result.namespaces.push(parse_namespace(buffer, value.start, value.end, budget, limits));
    } else if (field === 2 || field === 3) {
      expect_wire('XmlElement', field, wire, 2);
      if (seen.has(field)) fail('ORIX_PROTO_XML_DUPLICATE_FIELD', 'Duplicate XmlElement scalar field', { field });
      seen.add(field);
      result[field === 2 ? 'namespace_uri' : 'name'] =
        decode_utf8(buffer, value.start, value.end, 'XmlElement.' + field, budget, limits);
    } else if (field === 4) {
      expect_wire('XmlElement', field, wire, 2);
      if (++budget.attributes > limits.max_attributes) fail('ORIX_PROTO_XML_ATTRIBUTE_LIMIT', 'Protobuf XML attribute limit exceeded');
      result.attributes.push(parse_attribute(buffer, value.start, value.end, budget, limits));
    } else if (field === 5) {
      expect_wire('XmlElement', field, wire, 2);
      result.children.push(parse_node(buffer, value.start, value.end, budget, limits, depth + 1));
    }
    // Unknown fields are skipped after their wire representation is bounded.
  }, 'XmlElement');
  if (!result.name) fail('ORIX_PROTO_XML_ELEMENT_NAME', 'XmlElement requires a non-empty name');
  const names = new Set();
  for (const item of result.attributes) {
    const key = item.namespace_uri + '\u0000' + item.name;
    if (names.has(key)) fail('ORIX_PROTO_XML_DUPLICATE_ATTRIBUTE', 'XmlElement contains duplicate attributes', { name: item.name, namespace_uri: item.namespace_uri });
    names.add(key);
  }
  const prefixes = new Map();
  for (const item of result.namespaces) {
    if (prefixes.has(item.prefix)) fail('ORIX_PROTO_XML_DUPLICATE_NAMESPACE', 'XmlElement contains duplicate namespace prefixes', { prefix: item.prefix });
    prefixes.set(item.prefix, item.uri);
  }
  return result;
}

function parse_node(buffer, start, end, budget, limits, depth) {
  if (depth > limits.max_depth) {
    fail('ORIX_PROTO_XML_DEPTH_LIMIT', 'Protobuf XML nesting depth exceeds configured limit', { depth, max_depth: limits.max_depth });
  }
  if (++budget.nodes > limits.max_nodes) {
    fail('ORIX_PROTO_XML_NODE_LIMIT', 'Protobuf XML node-count limit exceeded', { max_nodes: limits.max_nodes });
  }
  let element = null;
  let text = null;
  let node_seen = false;
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('XmlNode', field, wire, 2);
      if (node_seen) fail('ORIX_PROTO_XML_ONEOF', 'XmlNode contains multiple oneof node values');
      node_seen = true;
      element = parse_element(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('XmlNode', field, wire, 2);
      if (node_seen) fail('ORIX_PROTO_XML_ONEOF', 'XmlNode contains multiple oneof node values');
      node_seen = true;
      text = decode_utf8(buffer, value.start, value.end, 'XmlNode.text', budget, limits);
    }
    // SourcePosition (field 3) and unknown fields are skipped.
  }, 'XmlNode');
  if (!node_seen) fail('ORIX_PROTO_XML_NODE_EMPTY', 'XmlNode must contain an element or text value');
  return element ? { kind: 'element', element } : { kind: 'text', text };
}

function attribute(element, name, namespace_uri = ANDROID_NS) {
  const found = element.attributes.find(item => item.name === name && item.namespace_uri === namespace_uri);
  return found ? found.value : null;
}

function integer_or_text(value) {
  if (value === null) return null;
  if (/^-?(?:0|[1-9][0-9]*)$/.test(value)) {
    const number = Number(value);
    if (Number.isSafeInteger(number)) return number;
  }
  return value;
}

function boolean_or_text(value) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}

function element_children(element) {
  return element.children.filter(item => item.kind === 'element').map(item => item.element);
}

/**
 * Decode an AAPT2 Resources.XmlNode protobuf document (AAB module manifest).
 * The parser is bounded, rejects malformed wire encodings and extracts only
 * manifest metadata; it does not resolve compiled resource references.
 */
export function parse_android_proto_xml(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Android protobuf XML input must be a Buffer');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Android protobuf XML options must be an object');
  const limits = {
    max_file_bytes: options.max_file_bytes ?? 16 * 1024 * 1024,
    max_fields: options.max_fields ?? 250_000,
    max_nodes: options.max_nodes ?? 20_000,
    max_elements: options.max_elements ?? 20_000,
    max_attributes: options.max_attributes ?? 100_000,
    max_namespaces: options.max_namespaces ?? 10_000,
    max_depth: options.max_depth ?? 128,
    max_string_bytes: options.max_string_bytes ?? 1 * 1024 * 1024,
    max_total_string_bytes: options.max_total_string_bytes ?? 8 * 1024 * 1024,
    max_output_items: options.max_output_items ?? 10_000,
  };
  for (const [name, value] of Object.entries(limits)) {
    const maximum = name === 'max_file_bytes' ? 64 * 1024 * 1024 :
      name === 'max_depth' ? 512 : name.includes('string_bytes') ? 16 * 1024 * 1024 : 1_000_000;
    bounded_integer(name, value, 1, maximum);
  }
  if (buffer.length > limits.max_file_bytes) {
    fail('ORIX_PROTO_XML_FILE_LIMIT', 'Android protobuf XML exceeds configured file-size limit', {
      size: buffer.length, max_file_bytes: limits.max_file_bytes,
    });
  }
  if (buffer.length === 0) fail('ORIX_PROTO_XML_EMPTY', 'Android protobuf XML input is empty');
  const budget = {
    fields: 0, nodes: 0, elements: 0, attributes: 0, namespaces: 0, strings: 0, string_bytes: 0,
    limits,
  };
  const root_node = parse_node(buffer, 0, buffer.length, budget, limits, 0);
  if (root_node.kind !== 'element' || root_node.element.name !== 'manifest' || root_node.element.namespace_uri !== '') {
    fail('ORIX_PROTO_XML_ROOT', 'AAB protobuf XML manifest must contain an unqualified manifest root element');
  }
  const root = root_node.element;
  const root_attributes = Object.create(null);
  for (const item of root.attributes) {
    if (item.namespace_uri === '') root_attributes[item.name] = item.value;
  }
  const children = element_children(root);
  const sdk = children.find(item => item.name === 'uses-sdk');
  const permissions = [];
  let output_truncated = false;
  for (const child of children) {
    if (!['uses-permission', 'uses-permission-sdk-23', 'uses-permission-sdk-m', 'uses-permission-sdk-28'].includes(child.name)) continue;
    const name = attribute(child, 'name');
    if (name === null) continue;
    if (permissions.length >= limits.max_output_items) {
      output_truncated = true;
      continue;
    }
    permissions.push({ name, maxSdkVersion: integer_or_text(attribute(child, 'maxSdkVersion')) });
  }
  const application_element = children.find(item => item.name === 'application');
  const components = [];
  if (application_element) {
    for (const child of element_children(application_element)) {
      if (!COMPONENT_TYPES.has(child.name)) continue;
      if (components.length >= limits.max_output_items) {
        output_truncated = true;
        continue;
      }
      components.push({
        type: child.name,
        name: attribute(child, 'name'),
        exported: boolean_or_text(attribute(child, 'exported')),
        permission: attribute(child, 'permission'),
        process: attribute(child, 'process'),
        authorities: attribute(child, 'authorities'),
        targetActivity: attribute(child, 'targetActivity'),
      });
    }
  }
  let application = null;
  if (application_element) {
    application = {
      label: attribute(application_element, 'label'),
      icon: attribute(application_element, 'icon'),
      debuggable: boolean_or_text(attribute(application_element, 'debuggable')),
      allowBackup: boolean_or_text(attribute(application_element, 'allowBackup')),
      usesCleartextTraffic: boolean_or_text(attribute(application_element, 'usesCleartextTraffic')),
      networkSecurityConfig: attribute(application_element, 'networkSecurityConfig'),
    };
  }
  return {
    decoded: true,
    package_name: root_attributes.package ?? null,
    version_code: integer_or_text(attribute(root, 'versionCode')),
    version_name: attribute(root, 'versionName'),
    permissions,
    components,
    application,
    counts: {
      chunks: 0,
      strings: budget.strings,
      elements: budget.elements,
      attributes: budget.attributes,
      resource_map_entries: 0,
    },
    output_truncated,
    notes: [
      'Decoded using the AAPT2 Resources.XmlNode protobuf structure; unknown protobuf fields were skipped by wire type.',
      'Manifest attribute values are reported as encoded strings; compiled resource items and resource-table references are not resolved.',
      'Component exported state is reported only when explicitly encoded; target SDK default rules are not inferred.',
    ],
  };
}
