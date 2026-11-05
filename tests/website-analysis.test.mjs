// JavaScript, tests/website-analysis.test.mjs, Node.js 20+, bounded offline HTML analysis.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze_website_project } from '../src/project/website.mjs';

test('website analysis inventories page structure and reports bounded review leads', () => {
  const html = [
    '<!doctype html>',
    '<html lang="en"><head><title>Demo site</title><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src self">',
    '<link rel="stylesheet" href="./assets/site.css">',
    '<script type="module" src="./app.js"></script>',
    '<script src="https://cdn.example.test/app.js?token=secret"></script></head>',
    '<body><a href="https://external.example.test/" target="_blank">external</a>',
    '<form action="http://collector.example.test/submit?token=secret" method="post"><input name="email"></form>',
    '<iframe src="https://embed.example.test/frame" sandbox></iframe><img src="/logo.png">',
    '<a href="javascript:alert(1)">bad</a><button onclick="run()">click</button></body></html>',
  ].join('\n');
  const report = analyze_website_project([
    { path: 'index.html', text: html, size_bytes: Buffer.byteLength(html) },
    { path: 'app.js', text: 'void 0;', size_bytes: 7 },
    { path: 'assets/site.css', text: 'body{}', size_bytes: 7 },
    { path: 'logo.png', text: null, size_bytes: 20 },
  ]);
  assert.equal(report.detected, true);
  assert.equal(report.summary.pages_seen, 1);
  assert.equal(report.summary.pages_analyzed, 1);
  assert.equal(report.pages[0].title, 'Demo site');
  assert.equal(report.pages[0].language, 'en');
  assert.equal(report.pages[0].scripts.external, 2);
  assert.equal(report.pages[0].scripts.inline, 0);
  assert.equal(report.pages[0].scripts.modules, 1);
  assert.equal(report.pages[0].stylesheets.count, 1);
  assert.equal(report.pages[0].links.external, 1);
  assert.equal(report.pages[0].forms[0].method, 'post');
  assert.equal(report.pages[0].iframes[0].sandboxed, true);
  assert.equal(report.pages[0].images, 1);
  assert.equal(report.pages[0].metadata.content_security_policy, true);
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_JAVASCRIPT_URL'));
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_INSECURE_FORM_ACTION'));
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_TARGET_BLANK_NO_REL'));
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_INLINE_EVENT_HANDLER'));
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_EXTERNAL_SCRIPT_NO_INTEGRITY'));
  const external_script = report.pages[0].scripts.references.find(item => item.kind === 'external');
  assert.deepEqual(external_script, { kind: 'external', origin: 'https://cdn.example.test', line: 5 });
  assert.equal(JSON.stringify(report).includes('token=secret'), false);
  assert.equal(report.coverage.complete, true);
});

test('website tokenizer ignores comments and raw script/style bodies as markup', () => {
  const html = '<!-- <img src="comment.png"> --><script>const x = "<img src=script.png>";</script><style>.x{content:"<iframe>"}</style><img src="real.png">';
  const report = analyze_website_project([{ path: 'index.html', text: html, size_bytes: html.length }]);
  assert.equal(report.pages[0].images, 1);
  assert.equal(report.pages[0].iframes.length, 0);
  assert.equal(report.pages[0].scripts.inline, 1);
});

test('website analysis identifies local references that escape the project root', () => {
  const html = '<html><body><a href="../../outside.html">outside</a></body></html>';
  const report = analyze_website_project([{ path: 'pages/index.html', text: html, size_bytes: html.length }]);
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_PATH_ESCAPE_REFERENCE'));
});

test('website analysis marks page, tag and finding limits as incomplete', () => {
  const one = '<html><body><p>one</p><p>two</p></body></html>';
  const two = '<html><body><p>three</p></body></html>';
  const report = analyze_website_project([
    { path: 'a.html', text: one, size_bytes: one.length },
    { path: 'b.html', text: two, size_bytes: two.length },
  ], { max_pages: 1, max_tags_per_page: 2 });
  assert.equal(report.summary.pages_seen, 2);
  assert.equal(report.summary.pages_analyzed, 1);
  assert.equal(report.coverage.complete, false);
  assert.equal(report.coverage.truncated, true);
  assert.ok(report.coverage.truncated_pages >= 1);
});

test('website analysis reports no detection for projects without HTML pages', () => {
  const report = analyze_website_project([{ path: 'app.js', text: 'void 0;', size_bytes: 7 }]);
  assert.equal(report.detected, false);
  assert.equal(report.confidence, 'not-detected');
  assert.equal(report.summary.pages_analyzed, 0);
});

test('website analysis rejects invalid limits before processing input', () => {
  assert.throws(() => analyze_website_project([], { max_pages: 0 }), /max_pages must be a positive integer/);
  assert.throws(() => analyze_website_project([], { max_tags_per_page: 20001 }), /max_tags_per_page must be a positive integer/);
});
