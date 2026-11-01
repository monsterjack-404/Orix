// JavaScript, src/cli.mjs, Node.js 20+, ORIX command-line interface.
import { inspectArtifact } from "./core/inspect.mjs";

function printHelp() {
  process.stdout.write("ORIX — Open Research & Intelligence eXplorer\n\nUsage:\n  node src/cli.mjs inspect <file> [--json]\n  node src/cli.mjs help\n");
}

async function main(args) {
  const [command, target, ...flags] = args;
  if (!command || command === "help" || command === "--help") return printHelp();
  if (command !== "inspect" || !target) {
    printHelp();
    process.exitCode = 2;
    return;
  }
  const result = await inspectArtifact(target);
  if (flags.includes("--json")) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    return;
  }
  for (const [key, value] of Object.entries(result)) process.stdout.write(key + ": " + value + "\n");
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write("ORIX error: " + error.message + "\n");
  process.exitCode = 1;
});
