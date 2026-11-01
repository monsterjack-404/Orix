#!/usr/bin/env node
// JavaScript, src/cli.mjs, Node.js 20+, executable ORIX command-line entry point.

import { run_cli } from './cli/main.mjs';

const exit_code = await run_cli();
process.exitCode = exit_code;
