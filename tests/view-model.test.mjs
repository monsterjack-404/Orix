// JavaScript, tests/view-model.test.mjs, Node.js 20+, viewer model contracts.
import test from'node:test';import assert from'node:assert/strict';import{build_report_view,filter_report_view}from'../src/reports/view-model.mjs';const hash='a'.repeat(64);function item(path,severity='high'){return{artifact:{path,name:path.split('/').at(-1),size_bytes:1024},integrity:{digest:hash},detection:{format:'PE'},parser:{status:'parsed'},indicators:[{rule_id:'ORIX-TEST-001',summary:'Review this record',severity,confidence:'observed'}]};}
test('normalizes an artifact report',()=>{const v=build_report_view({schema_version:'orix.artifact.v1',...item('/tmp/a.exe')});assert.equal(v.kind,'artifact');assert.equal(v.summary.items,1);assert.equal(v.records[0].sha256,hash);});
test('filters scan inventory by query, severity and format',()=>{const v=build_report_view({schema_version:'orix.scan.v1',scan:{root:'/work'},artifacts:[item('/work/a.exe'),{...item('/work/b.bin','low'),detection:{format:'Unknown'}}]});assert.equal(filter_report_view(v,{severity:'high'}).length,1);assert.equal(filter_report_view(v,{format:'Unknown'}).length,1);assert.equal(filter_report_view(v,{query:'ORIX-TEST'}).length,2);});
test('normalizes project findings without matched credential values',()=>{const secret='private-secret';const v=build_report_view({schema_version:'orix.project.v1',project:{root:'/work'},files:[{path:'src/a.js',sha256:hash,language:'JavaScript'}],findings:[{file:'src/a.js',line:7,rule_id:'ORIX-SECRET-001',severity:'high',label:'Credential match',matched_value:secret}]});assert.equal(v.records[0].findings[0].line,7);assert.equal(JSON.stringify(v).includes(secret),false);});
test('rejects unsupported schemas and malformed identities',()=>{assert.throws(()=>build_report_view({schema_version:'orix.unknown.v1'}),/supports/);assert.throws(()=>build_report_view({schema_version:'orix.scan.v1',artifacts:[{}]}),/Artifact identity/);assert.throws(()=>build_report_view({schema_version:'orix.project.v1',files:[{path:'x',sha256:'bad'}]}),/Invalid project SHA-256/);});

test('normalizes Rizin import reports as searchable symbol inventory without mislabeling imports as findings',()=>{
  const report={
    schema_version:'orix.rizin-imports.v1',
    provider:{id:'rizin.static',engine_version:'0.8.2'},
    artifact:{path:'/samples/app.elf',size_bytes:4096,sha256:hash,stable_during_analysis:true},
    imports:[
      {name:'SSL_connect',library:'libssl.so',ordinal:1,bind:'GLOBAL',type:'FUNC',plt:4096},
      {name:'open',library:'libc.so.6',ordinal:2,bind:'GLOBAL',type:'FUNC',plt:8192},
    ],
  };
  const view=build_report_view(report);
  assert.equal(view.kind,'provider-imports');
  assert.equal(view.summary.items,2);
  assert.equal(view.summary.bytes,4096);
  assert.equal(view.summary.findings,0);
  assert.equal(filter_report_view(view,{query:'SSL_connect'}).length,1);
  assert.equal(filter_report_view(view,{query:'libssl.so'}).length,1);
  const ssl_record=view.records.find(record=>record.name==='SSL_connect');
  assert.equal(ssl_record.sha256,hash);
  assert.equal(ssl_record.library,'libssl.so');
  assert.equal(ssl_record.raw.import.library,'libssl.so');
});

test('normalizes explicit provider doctor reports',()=>{
  const view=build_report_view({
    schema_version:'orix.provider-probe.v1',
    provider:{id:'rizin.static',engine_version:'0.8.2',executable:'/opt/rizin/bin/rizin'},
    runtime:{platform:'linux',architecture:'x64',node_version:'v22.0.0'},
    status:'available',
  });
  assert.equal(view.kind,'provider-probe');
  assert.equal(view.records[0].parser_status,'available');
  assert.equal(view.records[0].name,'rizin.static 0.8.2');
});

test('rejects malformed Rizin provider report identities',()=>{
  assert.throws(()=>build_report_view({
    schema_version:'orix.rizin-imports.v1',
    provider:{id:'rizin.static'},
    artifact:{path:'/samples/a',size_bytes:1,sha256:'bad'},
    imports:[],
  }),/valid artifact identity/);
});
