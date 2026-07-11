#!/usr/bin/env bash
# Dev launcher for the EDDMC Distributed Behavioural Fingerprint Registry.
# Run from anywhere -- it cds to the repo root so `registry` resolves
# as a package regardless of the caller's working directory.
set -e
cd "$(dirname "$0")/.."
export EDDMC_REGISTRY_AUTO_CONFIRM="${EDDMC_REGISTRY_AUTO_CONFIRM:-true}"
uvicorn registry.app:app --host 0.0.0.0 --port "${EDDMC_REGISTRY_PORT:-8321}" --reload
