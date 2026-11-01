// JavaScript, src/cli/help.mjs, Node.js 20+, canonical CLI help text.

export const HELP_TEXT = `ORIX — Open Research & Intelligence eXplorer
Understand. Analyze. Engineer.

USAGE
  orix inspect <file> [options]
  orix scan <directory> [options]
  orix formats
  orix help

COMMANDS
  inspect <file>       Hash and statically inspect one regular file.
  scan <directory>     Inventory a directory and inspect discovered files.
  formats              List signatures recognized by the format registry.
  help                 Print this help text.

OPTIONS
  --json               Emit machine-readable JSON.
  --markdown           Emit a Markdown report (default).
  --format <format>    Select json or markdown.
  --out <path>         Create a new report file; existing files are never overwritten.
  --no-strings         Disable printable ASCII and UTF-16LE string extraction.
  --strings-limit <n>  Maximum strings retained per file (default: 2000).
  --max-files <n>      Maximum directory files (default: 10000).
  --max-directories <n> Maximum directories examined (default: 10000).
  --max-entries <n>    Maximum directory entries examined (default: 100000).
  --max-depth <n>      Maximum directory depth (default: 24).
  --max-read-mib <n>   Maximum prefix parsed per file in MiB (default: 16).
  --max-file-mib <n>   Maximum full file hashed in MiB (default: 128).
  --concurrency <n>    Concurrent files during scan (default: 4; max: 32).
  -h, --help           Print help.

EXAMPLES
  orix inspect ./sample.exe
  orix inspect ./sample.elf --json --out ./sample-report.json
  orix scan ./build --max-files 5000 --concurrency 4 --markdown
  orix formats

SAFETY AND SCOPE
  ORIX performs local, static, read-only analysis. It does not execute inspected files,
  inject into processes, bypass access controls, or contact remote services. Symlinks
  are not followed. File count, depth, size, concurrency, parser counts, and extracted
  strings are bounded. A recognized signature is not a malware verdict.
`;
