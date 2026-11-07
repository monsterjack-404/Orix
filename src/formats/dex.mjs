// JavaScript, src/formats/dex.mjs, Node.js 20+, bounded DEX metadata parser.
// This parser does not decode bytecode instructions or execute artifacts.
import { createHash } from 'node:crypto';
import { OrixError } from '../core/errors.mjs';
import { parse_dex_semantics } from './dex-semantics.mjs';
const HEADER=112, NO_INDEX=0xffffffff;
const MAP_NAMES=new Map([[0,'header_item'],[1,'string_id_item'],[2,'type_id_item'],[3,'proto_id_item'],[4,'field_id_item'],[5,'method_id_item'],[6,'class_def_item'],[7,'call_site_id_item'],[8,'method_handle_item'],[0x1000,'map_list'],[0x1001,'type_list'],[0x2000,'class_data_item'],[0x2001,'code_item'],[0x2002,'string_data_item'],[0x2003,'debug_info_item'],[0x2004,'annotation_item'],[0x2005,'encoded_array_item'],[0x2006,'annotations_directory_item']]);
function fail(code,message,details={}){throw new OrixError(code,message,{details,recoverable:true});}
function range(count,off,size,label,fileSize){if(count===0){if(off!==0)fail('ORIX_DEX_EMPTY_TABLE_OFFSET','DEX empty '+label+' table must have offset zero',{count,off});return;}const bytes=count*size;if(!Number.isSafeInteger(bytes)||off<HEADER||off%4!==0||off>fileSize-bytes)fail('ORIX_DEX_TABLE_RANGE','DEX '+label+' table exceeds file bounds or is misaligned',{count,off,size,fileSize});}
function uleb(b,off,end){let v=0;for(let i=0;i<5;i++){if(off+i>=end)fail('ORIX_DEX_LEB128_TRUNCATED','DEX ULEB128 is truncated',{off});const x=b[off+i];if(i===4&&(x&0xf0))fail('ORIX_DEX_LEB128_OVERFLOW','DEX ULEB128 exceeds 32 bits',{off});v|=(x&127)<<(i*7);if(!(x&128))return {value:v>>>0,bytes:i+1};}fail('ORIX_DEX_LEB128_OVERFLOW','DEX ULEB128 exceeds five bytes',{off});}
function readString(b,off,end,max){
 const n=uleb(b,off,end),start=off+n.bytes,scanEnd=Math.min(end,start+max+1);
 let stop=start;
 while(stop<scanEnd&&b[stop]!==0)stop++;
 if(stop>=scanEnd)fail('ORIX_DEX_STRING_LIMIT','DEX string is unterminated or exceeds per-string limit',{off,max});
 const bytes=b.subarray(start,stop),pieces=[],chunk=[];
 let units=0;
 const append=unit=>{chunk.push(unit);units++;if(chunk.length===8192)pieces.push(String.fromCharCode(...chunk.splice(0,chunk.length)));};
 for(let i=0;i<bytes.length;){
  const first=bytes[i++];
  if(first>=0x01&&first<=0x7f){append(first);continue;}
  if((first&0xe0)===0xc0){
   if(i>=bytes.length||(bytes[i]&0xc0)!==0x80)fail('ORIX_DEX_STRING_ENCODING','DEX MUTF-8 has an invalid two-byte sequence',{off,byte_offset:i-1});
   const second=bytes[i++],unit=((first&0x1f)<<6)|(second&0x3f);
   if((unit===0&&(first!==0xc0||second!==0x80))||(unit!==0&&unit<0x80))fail('ORIX_DEX_STRING_ENCODING','DEX MUTF-8 contains a non-canonical two-byte sequence',{off,byte_offset:i-2});
   append(unit);continue;
  }
  if((first&0xf0)===0xe0){
   if(i+1>=bytes.length||(bytes[i]&0xc0)!==0x80||(bytes[i+1]&0xc0)!==0x80)fail('ORIX_DEX_STRING_ENCODING','DEX MUTF-8 has an invalid three-byte sequence',{off,byte_offset:i-1});
   const second=bytes[i++],third=bytes[i++],unit=((first&0x0f)<<12)|((second&0x3f)<<6)|(third&0x3f);
   if(unit<0x800)fail('ORIX_DEX_STRING_ENCODING','DEX MUTF-8 contains a non-canonical three-byte sequence',{off,byte_offset:i-3});
   append(unit);continue;
  }
  fail('ORIX_DEX_STRING_ENCODING','DEX string contains a byte forbidden by MUTF-8',{off,byte_offset:i-1,byte:first});
 }
 if(units!==n.value)fail('ORIX_DEX_STRING_LENGTH','DEX MUTF-8 decoded UTF-16 length does not match utf16_size',{off,declared:n.value,actual:units});
 if(chunk.length)pieces.push(String.fromCharCode(...chunk));
 return {utf16_length:n.value,byte_length:bytes.length,value:pieces.join('')};
}
function parseMap(b,off,end,max){if(!off||off%4||off>end-4)fail('ORIX_DEX_MAP_RANGE','DEX map_list offset is invalid',{off,end});const count=b.readUInt32LE(off);if(count>max||off>end-(4+count*12))fail('ORIX_DEX_MAP_LIMIT','DEX map_list exceeds bounds or configured item limit',{count,max});const out=[],seen=new Set();let prev=-1;for(let i=0;i<count;i++){const p=off+4+i*12,type=b.readUInt16LE(p),unused=b.readUInt16LE(p+2),size=b.readUInt32LE(p+4),itemOff=b.readUInt32LE(p+8);if(unused||!size||seen.has(type)||itemOff>=end||(i>0&&itemOff<=prev))fail('ORIX_DEX_MAP_INVALID','DEX map item has invalid reserved field, size, type or ordering',{i,type,size,itemOff,prev});seen.add(type);prev=itemOff;out.push({type,name:MAP_NAMES.get(type)??'unknown',size,offset:itemOff});}if(!out.some(x=>x.type===0&&x.size===1&&x.offset===0)||!out.some(x=>x.type===0x1000&&x.size===1&&x.offset===off))fail('ORIX_DEX_MAP_REQUIRED_ITEMS','DEX map must describe its header and map_list');return out;}
/** Parse DEX 035-040 header, index tables, class definitions and map metadata. */
export function parse_dex(buffer,options={}){
 if(!Buffer.isBuffer(buffer))throw new TypeError('parse_dex requires a Buffer');if(!options||typeof options!=='object'||Array.isArray(options))throw new TypeError('DEX options must be an object');
 const maxFile=options.max_file_bytes??134217728,maxItems=options.max_table_items??250000,maxMap=options.max_map_items??4096,maxString=options.max_string_bytes??1048576,maxTotal=options.max_total_string_bytes??33554432,maxOutput=options.max_output_items??10000;
 for(const [n,v,min,max] of [['max_file_bytes',maxFile,HEADER,536870912],['max_table_items',maxItems,1,1000000],['max_map_items',maxMap,1,65536],['max_string_bytes',maxString,1,16777216],['max_total_string_bytes',maxTotal,1,268435456],['max_output_items',maxOutput,1,100000]])if(!Number.isSafeInteger(v)||v<min||v>max)throw new TypeError(n+' is outside its supported range');
 if(buffer.length<HEADER)fail('ORIX_DEX_TRUNCATED_HEADER','DEX header is shorter than 112 bytes',{actual:buffer.length});if(buffer.length>maxFile)fail('ORIX_DEX_FILE_LIMIT','DEX input exceeds configured file limit',{actual:buffer.length,maxFile});
 if(buffer.toString('ascii',0,4)!=='dex\n'||buffer[7]!==0)fail('ORIX_DEX_BAD_MAGIC','Input does not use a supported DEX magic value');const version=buffer.toString('ascii',4,7);if(!['035','037','038','039','040'].includes(version))fail('ORIX_DEX_UNSUPPORTED_VERSION','Only DEX versions 035, 037, 038, 039 and 040 are supported',{version});
 const fileSize=buffer.readUInt32LE(32),headerSize=buffer.readUInt32LE(36),endian=buffer.readUInt32LE(40);if(headerSize!==HEADER)fail('ORIX_DEX_HEADER_SIZE','DEX header_size must equal 112',{headerSize});if(endian!==0x12345678)fail('ORIX_DEX_ENDIAN','DEX reverse-endian or invalid endian tag is unsupported',{endian});if(fileSize<HEADER||fileSize!==buffer.length)fail('ORIX_DEX_FILE_SIZE','DEX declared file_size is outside supplied bytes',{fileSize,bufferLength:buffer.length});
 const linkSize=buffer.readUInt32LE(44),linkOff=buffer.readUInt32LE(48),mapOff=buffer.readUInt32LE(52);if((linkSize===0)!==(linkOff===0)||(linkSize&&(linkOff<HEADER||linkOff>fileSize-linkSize)))fail('ORIX_DEX_LINK_RANGE','DEX link section is inconsistent or out of bounds',{linkSize,linkOff});
 const names=['string_ids','type_ids','proto_ids','field_ids','method_ids','class_defs'],sizes=[4,4,12,8,8,32],counts={},offsets={};for(let i=0;i<names.length;i++){const p=56+i*8;counts[names[i]]=buffer.readUInt32LE(p);offsets[names[i]]=buffer.readUInt32LE(p+4);if(counts[names[i]]>maxItems)fail('ORIX_DEX_TABLE_LIMIT','DEX '+names[i]+' count exceeds configured limit',{count:counts[names[i]],maxItems});range(counts[names[i]],offsets[names[i]],sizes[i],names[i],fileSize);}
 const dataSize=buffer.readUInt32LE(104),dataOff=buffer.readUInt32LE(108);if((dataSize===0)!==(dataOff===0)||(dataSize&&(dataOff<HEADER||dataOff%4||dataSize%4||dataOff>fileSize-dataSize)))fail(dataSize%4?'ORIX_DEX_DATA_ALIGNMENT':'ORIX_DEX_DATA_RANGE','DEX data section is inconsistent, misaligned or out of bounds',{dataSize,dataOff,fileSize});const dataEnd=dataOff+dataSize;if(linkSize&&(linkOff<dataEnd||linkOff+linkSize!==fileSize))fail('ORIX_DEX_LINK_RANGE','DEX link section overlaps data or does not terminate the file',{linkSize,linkOff,dataEnd,fileSize});if(!linkSize&&dataSize&&dataEnd!==fileSize)fail('ORIX_DEX_DATA_RANGE','DEX data section must terminate a file without link data',{dataSize,dataOff,dataEnd,fileSize});

 if(mapOff<dataOff||mapOff>dataOff+dataSize-4)fail('ORIX_DEX_MAP_DATA_RANGE','DEX map_list must be inside the declared data section',{mapOff,dataOff,dataSize});
 const mapItems=parseMap(buffer.subarray(0,fileSize),mapOff,fileSize,maxMap);if(mapOff>dataEnd-(4+mapItems.length*12))fail('ORIX_DEX_MAP_DATA_RANGE','DEX map_list extends beyond the declared data section',{mapOff,itemCount:mapItems.length,dataEnd});const preDataWidths=new Map([[1,4],[2,4],[3,12],[4,8],[5,8],[6,32],[7,4],[8,8]]);for(const item of mapItems){const width=preDataWidths.get(item.type);if(width!==undefined){const bytes=item.size*width;if(item.offset<HEADER||item.offset>=dataOff||!Number.isSafeInteger(bytes)||bytes>dataOff-item.offset)fail('ORIX_DEX_MAP_PRE_DATA_RANGE','DEX map entry for a fixed index section must be wholly before data_off',{type:item.type,offset:item.offset,size:item.size,width,dataOff});}else if(item.type!==0&&(item.offset<dataOff||item.offset>=dataEnd))fail('ORIX_DEX_MAP_DATA_RANGE','DEX map entry must point inside the declared data section',{type:item.type,offset:item.offset,dataOff,dataEnd});} const tableRanges=names.flatMap((name,i)=>counts[name]?[{name,start:offsets[name],end:offsets[name]+counts[name]*sizes[i]}]:[]).concat(mapItems.filter(item=>item.type===7||item.type===8).map(item=>({name:item.type===7?'call_site_ids':'method_handles',start:item.offset,end:item.offset+item.size*(item.type===7?4:8)}))).sort((a,b)=>a.start-b.start);for(let i=0;i<tableRanges.length;i++){if(tableRanges[i].end>dataOff||(i>0&&tableRanges[i].start<tableRanges[i-1].end))fail('ORIX_DEX_TABLE_OVERLAP','DEX fixed index tables overlap or extend into the data section',{current:tableRanges[i],previous:tableRanges[i-1]??null,dataOff});}const mapByType=new Map(mapItems.map(item=>[item.type,item]));for(let i=0;i<names.length;i++){const item=mapByType.get(i+1),count=counts[names[i]],off=offsets[names[i]];if(count&&(!item||item.size!==count||item.offset!==off))fail('ORIX_DEX_MAP_TABLE_MISMATCH','DEX map entry does not match header table metadata',{table:names[i],count,off,map:item??null});if(!count&&item)fail('ORIX_DEX_MAP_TABLE_MISMATCH','DEX map contains an entry for an empty header table',{table:names[i],map:item});}

 const callSiteMap=mapByType.get(7);if(callSiteMap){let previousCallSite=-1;for(let i=0;i<callSiteMap.size;i++){const callSiteOff=buffer.readUInt32LE(callSiteMap.offset+i*4);if(callSiteOff<dataOff||callSiteOff>=dataEnd)fail('ORIX_DEX_CALL_SITE_OFFSET','DEX call_site_id_item references data outside the data section',{i,callSiteOff,dataOff,dataEnd});if(callSiteOff<=previousCallSite)fail('ORIX_DEX_CALL_SITE_ORDER','DEX call_site_ids must be sorted by call_site_off',{i,callSiteOff,previousCallSite});uleb(buffer,callSiteOff,dataEnd);previousCallSite=callSiteOff;}}
 const methodHandleMap=mapByType.get(8);if(methodHandleMap){for(let i=0;i<methodHandleMap.size;i++){const p=methodHandleMap.offset+i*8,handleType=buffer.readUInt16LE(p),unused0=buffer.readUInt16LE(p+2),memberIndex=buffer.readUInt16LE(p+4),unused1=buffer.readUInt16LE(p+6);if(handleType>8)fail('ORIX_DEX_METHOD_HANDLE_TYPE','DEX method_handle_item has an unknown handle type',{i,handleType});if(unused0!==0||unused1!==0)fail('ORIX_DEX_METHOD_HANDLE_RESERVED','DEX method_handle_item reserved fields must be zero',{i,unused0,unused1});const memberCount=handleType<=3?counts.field_ids:counts.method_ids;if(memberIndex>=memberCount)fail('ORIX_DEX_METHOD_HANDLE_INDEX','DEX method_handle_item references an invalid field or method index',{i,handleType,memberIndex,memberCount});}}
 const strings=[],stringMeta=[];let total=0;for(let i=0;i<counts.string_ids;i++){const off=buffer.readUInt32LE(offsets.string_ids+i*4);if(off<dataOff||off>=dataOff+dataSize)fail('ORIX_DEX_STRING_OFFSET','DEX string_data offset is outside data section',{i,off});const s=readString(buffer,off,dataOff+dataSize,maxString);if(i>0&&stringMeta[i-1].value>=s.value)fail('ORIX_DEX_STRING_ORDER','DEX string_ids must be unique and sorted by UTF-16 code-unit value',{index:i,previous:stringMeta[i-1].value,current:s.value});total+=s.byte_length;if(total>maxTotal)fail('ORIX_DEX_STRING_BUDGET','DEX string bytes exceed aggregate limit',{maxTotal});stringMeta.push(s);if(i<maxOutput)strings.push({index:i,...s});}
 const types=[],typeMeta=[];let previousDescriptorIndex=-1;for(let i=0;i<counts.type_ids;i++){const descriptorIndex=buffer.readUInt32LE(offsets.type_ids+i*4);if(descriptorIndex>=counts.string_ids)fail('ORIX_DEX_TYPE_INDEX','DEX type descriptor index is invalid',{i,descriptorIndex});if(descriptorIndex<=previousDescriptorIndex)fail('ORIX_DEX_TYPE_ORDER','DEX type_ids must be unique and sorted by descriptor string index',{i,descriptorIndex,previousDescriptorIndex});previousDescriptorIndex=descriptorIndex;const item={index:i,descriptor_index:descriptorIndex,descriptor:stringMeta[descriptorIndex]?.value??null};typeMeta.push(item);if(i<maxOutput)types.push(item);}
 const classes=[];let previousClassIndex=-1;for(let i=0;i<counts.class_defs;i++){const p=offsets.class_defs+i*32,classIndex=buffer.readUInt32LE(p),access=buffer.readUInt32LE(p+4),superIndex=buffer.readUInt32LE(p+8),interfaces=buffer.readUInt32LE(p+12),source=buffer.readUInt32LE(p+16),annotations=buffer.readUInt32LE(p+20),classData=buffer.readUInt32LE(p+24),staticValues=buffer.readUInt32LE(p+28);if(classIndex<=previousClassIndex)fail('ORIX_DEX_CLASS_ORDER','DEX class_defs must be unique and sorted by class_idx',{i,classIndex,previousClassIndex});previousClassIndex=classIndex;if(classIndex>=counts.type_ids||(superIndex!==NO_INDEX&&superIndex>=counts.type_ids)||(source!==NO_INDEX&&source>=counts.string_ids))fail('ORIX_DEX_CLASS_INDEX','DEX class definition has invalid type or source index',{i,classIndex,superIndex,source});for(const [label,value] of [['interfaces',interfaces],['annotations',annotations],['class_data',classData],['static_values',staticValues]])if(value&&(value<dataOff||value>=dataOff+dataSize))fail('ORIX_DEX_CLASS_OFFSET','DEX class '+label+' offset is outside data section',{i,value});if(interfaces){if(interfaces%4||interfaces>dataOff+dataSize-4)fail('ORIX_DEX_INTERFACE_RANGE','DEX interfaces type_list is invalid',{i,interfaces});const n=buffer.readUInt32LE(interfaces);if(n>maxItems||interfaces>dataOff+dataSize-4-n*2)fail('ORIX_DEX_INTERFACE_RANGE','DEX interfaces type_list exceeds bounds',{i,n});for(let j=0;j<n;j++)if(buffer.readUInt16LE(interfaces+4+j*2)>=counts.type_ids)fail('ORIX_DEX_INTERFACE_INDEX','DEX interface type index is invalid',{i,j});}if(i<maxOutput)classes.push({index:i,class_index:classIndex,descriptor:typeMeta[classIndex]?.descriptor??null,access_flags:access,superclass_index:superIndex,superclass:superIndex===NO_INDEX?null:typeMeta[superIndex]?.descriptor??null,source_file_index:source,source_file:source===NO_INDEX?null:stringMeta[source]?.value??null,interfaces_off:interfaces,annotations_off:annotations,class_data_off:classData,static_values_off:staticValues});}
 const semantics=parse_dex_semantics({
  buffer, offsets, counts, data:{offset:dataOff,size:dataSize,end:dataEnd},
  types:typeMeta, strings:stringMeta, map_items:mapItems,
  max_items:maxItems, max_output_items:maxOutput,
  max_instruction_units:options.max_instruction_units??20000000,
 });
 const expectedAdler=buffer.readUInt32LE(8);
 let adlerA=1,adlerB=0;
 for(let i=12;i<buffer.length;i++){adlerA=(adlerA+buffer[i])%65521;adlerB=(adlerB+adlerA)%65521;}
 const actualAdler=((adlerB<<16)|adlerA)>>>0;
 const expectedSha1=buffer.subarray(12,32).toString('hex');
 const actualSha1=createHash('sha1').update(buffer.subarray(32)).digest('hex');
 const integrity={
  adler32_verified:expectedAdler===actualAdler,
  signature_sha1_verified:expectedSha1===actualSha1,
  adler32_expected:expectedAdler,
  adler32_actual:actualAdler,
  signature_sha1_expected:expectedSha1,
  signature_sha1_actual:actualSha1,
 };
 return {
  format:'DEX',version,file_size:fileSize,header_size:headerSize,endian:'little-endian',
  checksum:expectedAdler,signature_sha1:expectedSha1,link:{size:linkSize,offset:linkOff},
  map_off:mapOff,data:{size:dataSize,offset:dataOff},counts,strings,types,classes,map_items:mapItems,
  ...semantics,integrity,
  output_truncated:Object.values(counts).some(n=>n>maxOutput)||semantics.class_data_summary.output_truncated,
  notes:[
   'DEX header, identifiers, prototypes, class data and code_item structure are validated within explicit limits.',
   'DEX Adler-32 and SHA-1 file-integrity fields are recomputed; these checks do not authenticate the APK publisher or replace APK signing verification.',
   ...semantics.notes,
   'DEX bytecode opcodes, operands, control flow, annotations, debug programs and decompilation are not decoded.',
   'APK ZIP containers and binary AndroidManifest.xml resources are not analyzed by this standalone parser.',
  ],
 };
}
