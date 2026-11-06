#!/usr/bin/env node
import { inspect_linux_cgroup_v2 } from '../src/providers/linux-cgroup-v2-preflight.mjs';

const report = await inspect_linux_cgroup_v2();
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
if (!report.supported) process.stdout.write('This host is not Linux; cgroup v2 preflight is unavailable.\n');
else if (!report.ready) process.stdout.write('No usable delegated ORIX cgroup v2 parent was verified. No cgroup state was changed.\n');
else process.stdout.write('Delegated cgroup v2 layout passed read-only preflight. Kernel enforcement still requires integration tests.\n');
