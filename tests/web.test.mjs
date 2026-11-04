// JavaScript, tests/web.test.mjs, Node.js 20+, static server boundary tests.
import test from'node:test';import assert from'node:assert/strict';import{create_web_server}from'../scripts/serve-web.mjs';
import{csv_cell}from'../web/csv.mjs';
test('serves allowlisted local assets with CSP and rejects other routes and methods',async()=>{const s=create_web_server();await new Promise((ok,fail)=>{s.once('error',fail);s.listen(0,'127.0.0.1',ok);});const origin='http://127.0.0.1:'+s.address().port;try{const page=await fetch(origin+'/');assert.equal(page.status,200);assert.match(await page.text(),/ORIX/);assert.match(page.headers.get('content-security-policy'),/connect-src 'none'/);assert.equal(page.headers.get('x-content-type-options'),'nosniff');assert.equal((await fetch(origin+'/src/reports/view-model.mjs')).status,200);assert.equal((await fetch(origin+'/package.json')).status,404);const denied=await fetch(origin+'/',{method:'POST'});assert.equal(denied.status,405);assert.equal(denied.headers.get('allow'),'GET, HEAD');}finally{await new Promise((ok,fail)=>s.close(e=>e?fail(e):ok()));}});

test('CSV export neutralizes spreadsheet formulas and preserves CSV quoting', () => {
  for (const formula of ['=1+1', '+SUM(A1:A2)', '-2+3', '@SUM(1,2)', '  =cmd']) {
    assert.ok(csv_cell(formula).startsWith('"\''));
  }
  assert.equal(csv_cell('safe,"quoted"\nvalue'), '"safe,""quoted"" value"');
  assert.equal(csv_cell(null), '""');
});
