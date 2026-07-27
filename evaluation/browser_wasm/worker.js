// EDDMC Evaluation — WASM worker: loads wasm_source.wasm and hammers
// hash_loop() forever. One of these runs per CPU core (see wasm_worker.html)
// to reproduce the thread-saturated, CPU-bound shape of an in-browser miner.
self.onmessage = async (e) => {
  if (e.data !== "start") return;
  const resp = await fetch("wasm_source.wasm");
  const bytes = await resp.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes);
  const { hash_loop } = instance.exports;

  let acc = 0;
  while (true) {
    acc ^= hash_loop(2_000_000);
    // yield briefly so the worker stays responsive to a stop message
    await new Promise((r) => setTimeout(r, 0));
    if (self._stop) break;
  }
  postMessage({ done: true, acc });
};

self.addEventListener("close", () => {
  self._stop = true;
});
