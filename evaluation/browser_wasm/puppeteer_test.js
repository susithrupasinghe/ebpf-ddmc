// EDDMC Evaluation — Puppeteer driver for the in-browser WASM miner-shaped
// workload. Launches Chromium with --single-process so the WASM worker load
// lands on one PID that's easy to correlate with EDDMC's process table, then
// hands that PID to results_capture.py for the duration of the run.
//
// Usage: node puppeteer_test.js [duration_seconds]
// Requires: npm install (in this directory) && node build_wasm.js first,
//           a static file server for this directory (see run_browser_test.sh),
//           eddmc daemon already running.
//
// Puppeteer's bundled Chromium is x64-only -- it has no Linux/arm64 build,
// so on an arm64 host (`uname -m` == aarch64) you need a system browser
// instead: `sudo apt install chromium-browser`, then either export
// CHROME_PATH=/usr/bin/chromium-browser or pass it as a 3rd CLI arg.
const puppeteer = require("puppeteer");
const { spawn } = require("child_process");
const path = require("path");

const DURATION = parseInt(process.argv[2] || "60", 10);
const SERVE_URL = process.argv[3] || "http://127.0.0.1:8899/wasm_worker.html";
const CHROME_PATH = process.env.CHROME_PATH || process.argv[4] || undefined;
const EVAL_DIR = path.join(__dirname, "..");

async function main() {
  const browser = await puppeteer.launch({
    headless: "new",
    executablePath: CHROME_PATH,
    args: [
      "--no-sandbox",           // required when running as root in a VM
      "--single-process",       // keep all worker CPU load on one traceable PID
      "--disable-dev-shm-usage",
    ],
  });

  const pid = browser.process().pid;
  console.log(`[puppeteer] browser pid=${pid}`);

  const page = await browser.newPage();
  await page.goto(SERVE_URL, { waitUntil: "load" });
  console.log(`[puppeteer] page loaded, running for ${DURATION}s`);

  const capture = spawn(
    "python3",
    [
      path.join(EVAL_DIR, "eddmc_eval.py"),
      "capture",
      "--track", "browser_wasm_miner_postfix",
      "--pid", String(pid),
      "--duration", String(DURATION),
    ],
    { stdio: "inherit" }
  );

  await new Promise((resolve) => capture.on("exit", resolve));
  await browser.close();
  console.log("[puppeteer] done");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
