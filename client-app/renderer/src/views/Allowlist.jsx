import { useState } from 'react';
import { usePolling } from '../hooks/usePolling.js';
import { Panel } from '../components/Panel.jsx';
import { Button } from '../components/Button.jsx';
import { StatusBadge } from '../components/Badge.jsx';
import tableStyles from '../components/Table.module.css';
import styles from './Allowlist.module.css';

export function Allowlist() {
  const detection = usePolling(async () => (await window.eddmc.config()).detection, 4000, {});
  const pending = usePolling(() => window.eddmc.registryPending(), 4000, null);
  const confirmed = usePolling(() => window.eddmc.registryConfirmed(), 4000, null);

  const [path, setPath] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg, setSubmitMsg] = useState(null);
  const [confirmingHash, setConfirmingHash] = useState(null);

  const registryReachable = Array.isArray(pending) && Array.isArray(confirmed);
  const localBinaries = detection.allowlist_binaries || [];

  async function handleSubmit(e) {
    e.preventDefault();
    if (!path.trim()) return;
    setSubmitting(true);
    setSubmitMsg(null);
    try {
      const resp = await window.eddmc.submitAllowlist(path.trim(), description.trim());
      if (resp?.error) {
        setSubmitMsg({ ok: false, text: resp.error });
      } else {
        setSubmitMsg({ ok: true, text: `Submitted — sha256 ${resp.sha256.slice(0, 12)}… (status: ${resp.status})` });
        setPath('');
        setDescription('');
      }
    } catch (err) {
      setSubmitMsg({ ok: false, text: String(err) });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleConfirm(sha256) {
    setConfirmingHash(sha256);
    try { await window.eddmc.registryConfirm(sha256); } finally { setConfirmingHash(null); }
  }

  return (
    <div className={styles.wrap}>
      <Panel title="Locally trusted binaries">
        <p className={styles.hint}>
          Path-pinned <em>and</em> hash-pinned: every scan re-hashes the file, so if a trusted
          binary's content changes it stops being exempted rather than being silently trusted.
        </p>
        <div className={tableStyles.wrap}>
          <table className={tableStyles.table}>
            <thead><tr><th>Path</th><th>SHA-256</th></tr></thead>
            <tbody>
              {localBinaries.map((b) => (
                <tr key={b.path}>
                  <td className={styles.pathCell}>{b.path}</td>
                  <td className={tableStyles.mono}>{b.sha256.slice(0, 16)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
          {localBinaries.length === 0 && <div className={tableStyles.empty}>No local entries yet.</div>}
        </div>
      </Panel>

      <Panel title="Submit to shared registry">
        <p className={styles.hint}>
          Hashes the file and submits it — it stays <StatusBadge status="pending">pending</StatusBadge> until
          a registry admin explicitly confirms it below. Submitting alone never grants trust.
        </p>
        <form className={styles.submitForm} onSubmit={handleSubmit}>
          <input
            className={styles.input}
            placeholder="/path/to/binary"
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
          <input
            className={styles.input}
            placeholder="Description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <Button type="submit" variant="primary" disabled={submitting || !path.trim()}>
            {submitting ? 'Submitting…' : 'Submit'}
          </Button>
        </form>
        {submitMsg && (
          <div className={submitMsg.ok ? styles.msgOk : styles.msgErr}>{submitMsg.text}</div>
        )}
      </Panel>

      <Panel title="Registry — pending review">
        {!registryReachable ? (
          <div className={tableStyles.empty}>
            Registry not reachable — check <code>fingerprint_registry.registry_url</code> and that the
            registry service is running.
          </div>
        ) : (
          <div className={tableStyles.wrap}>
            <table className={tableStyles.table}>
              <thead><tr><th>SHA-256</th><th>Description</th><th>Submitted by</th><th>Count</th><th></th></tr></thead>
              <tbody>
                {pending.map((p) => (
                  <tr key={p.sha256}>
                    <td className={tableStyles.mono}>{p.sha256.slice(0, 16)}…</td>
                    <td>{p.description || '—'}</td>
                    <td className={styles.nodeCell}>{p.submitted_by_node?.slice(0, 12) || '—'}</td>
                    <td className={tableStyles.mono}>{p.submission_count}</td>
                    <td>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={confirmingHash === p.sha256}
                        onClick={() => handleConfirm(p.sha256)}
                      >
                        {confirmingHash === p.sha256 ? 'Confirming…' : 'Confirm'}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {pending.length === 0 && <div className={tableStyles.empty}>Nothing pending review.</div>}
          </div>
        )}
      </Panel>

      {registryReachable && (
        <Panel title={`Registry — confirmed (${confirmed.length})`}>
          <div className={tableStyles.wrap}>
            <table className={tableStyles.table}>
              <thead><tr><th>SHA-256</th><th>Description</th><th>Confirmed</th></tr></thead>
              <tbody>
                {confirmed.map((c) => (
                  <tr key={c.sha256}>
                    <td className={tableStyles.mono}>{c.sha256.slice(0, 16)}…</td>
                    <td>{c.description || '—'}</td>
                    <td className={styles.nodeCell}>{formatTime(c.confirmed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {confirmed.length === 0 && <div className={tableStyles.empty}>No confirmed entries yet.</div>}
          </div>
        </Panel>
      )}
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}
