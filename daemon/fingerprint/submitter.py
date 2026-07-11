"""
EDDMC - Fingerprint Submitter

Sends a packaged fingerprint to the central registry server over HTTP,
entirely in a background thread so registry latency or unavailability
never affects local detection/mitigation. One retry is attempted after
5 minutes if the initial submission fails; after that the fingerprint is
dropped -- a local detection is never blocked by registry availability.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request

logger = logging.getLogger("eddmc.fingerprint.submitter")

RETRY_DELAY_S = 5 * 60


class FingerprintSubmitter:
    def __init__(self, registry_url: str, timeout: float = 5.0):
        self._url = registry_url.rstrip("/") + "/api/v1/fingerprints"
        self._timeout = timeout

    def submit_async(self, fingerprint: dict):
        t = threading.Thread(
            target=self._submit_with_retry,
            args=(fingerprint,),
            daemon=True,
            name="fingerprint-submitter",
        )
        t.start()

    def _submit_with_retry(self, fingerprint: dict):
        if self._post(fingerprint):
            return
        logger.warning(
            "Registry submission failed for %s -- retrying in %ds",
            fingerprint.get("fingerprint_id"),
            RETRY_DELAY_S,
        )
        threading.Timer(RETRY_DELAY_S, self._post, args=(fingerprint,)).start()

    def _post(self, fingerprint: dict) -> bool:
        try:
            body = json.dumps(fingerprint).encode()
            req = urllib.request.Request(
                self._url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                ok = 200 <= resp.status < 300
                if ok:
                    logger.info(
                        "Fingerprint %s submitted to registry (status=%s)",
                        fingerprint.get("fingerprint_id"),
                        resp.status,
                    )
                return ok
        except (urllib.error.URLError, OSError) as exc:
            logger.debug("Registry unreachable: %s", exc)
            return False
