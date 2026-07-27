// EDDMC Evaluation — compiles wasm_source.wat -> wasm_source.wasm using the
// `wabt` npm package (pure JS/WASM port of the WABT toolkit, no system
// compiler needed). Run once after `npm install`:
//   node build_wasm.js
const fs = require("fs");
const path = require("path");

async function main() {
  const wabt = await require("wabt")();

  const watPath = path.join(__dirname, "wasm_source.wat");
  const wasmPath = path.join(__dirname, "wasm_source.wasm");

  const wat = fs.readFileSync(watPath, "utf8");
  const wasmModule = wabt.parseWat(watPath, wat);
  const { buffer } = wasmModule.toBinary({});

  fs.writeFileSync(wasmPath, Buffer.from(buffer));
  console.log(`[build] wrote ${wasmPath} (${buffer.length} bytes)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
