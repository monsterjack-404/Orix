// JavaScript, src/mcp.mjs, Node.js 20+, ORIX stdio MCP server executable.

import { start_mcp_server } from './mcp/server.mjs';

try {
  await start_mcp_server();
} catch (error) {
  process.stderr.write('ORIX MCP startup failure: ' + (error?.message ?? String(error)) + '\n');
  process.exitCode = 1;
}
