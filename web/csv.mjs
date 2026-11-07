// JavaScript, web/csv.mjs, browser ES module, spreadsheet-safe CSV cell encoding.

export function csv_cell(value) {
  let text = String(value ?? '');
  if (/^[\s\uFEFF]*[=+\-@]/.test(text)) text = "'" + text;
  return '"' + text.replaceAll('"', '""').replace(/[\r\n]+/g, ' ') + '"';
}
