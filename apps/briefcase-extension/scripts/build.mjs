import { build } from "esbuild";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const root = path.join(__dirname, "..");
const outdir = path.join(root, "extension", "dist");

await mkdir(outdir, { recursive: true });

const common = {
  bundle: true,
  format: "esm",
  sourcemap: true,
  target: "es2022",
  platform: "browser",
  logLevel: "info",
};

await build({
  ...common,
  entryPoints: [path.join(root, "src", "extension", "background.ts")],
  outfile: path.join(outdir, "background.js"),
});

await build({
  ...common,
  entryPoints: [path.join(root, "src", "extension", "popup.ts")],
  outfile: path.join(outdir, "popup.js"),
});

