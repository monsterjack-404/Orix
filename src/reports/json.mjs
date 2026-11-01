// JavaScript, src/reports/json.mjs, Node.js 20+, deterministic JSON serialization.

export function render_json(report, options = {}) {
  const indentation = options.compact ? 0 : 2;
  return `${JSON.stringify(report, null, indentation)}\n`;
}
