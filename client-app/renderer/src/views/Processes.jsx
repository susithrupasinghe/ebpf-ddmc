import { Fragment, useState } from 'react';
import { usePolling } from '../hooks/usePolling.js';
import { Panel } from '../components/Panel.jsx';
import { TierBadge } from '../components/Badge.jsx';
import { ScoreBar } from '../components/ScoreBar.jsx';
import { Button } from '../components/Button.jsx';
import tableStyles from '../components/Table.module.css';
import styles from './Processes.module.css';

export function Processes() {
  const processes = usePolling(() => window.eddmc.processes(), 2000, []);
  const [filter, setFilter] = useState('all');
  const [busyPid, setBusyPid] = useState(null);
  const [expanded, setExpanded] = useState(null);

  const rows = processes
    .filter((p) => (filter === 'all' ? true : (p.confidence || 'NONE') !== 'NONE'))
    .sort((a, b) => (b.score || 0) - (a.score || 0));

  async function handleRevoke(pid) {
    setBusyPid(pid);
    try { await window.eddmc.revoke(pid); } finally { setBusyPid(null); }
  }

  async function handleKill(pid) {
    if (!confirm(`Send a kill signal to pid ${pid}? This cannot be undone.`)) return;
    setBusyPid(pid);
    try { await window.eddmc.kill(pid); } finally { setBusyPid(null); }
  }

  return (
    <Panel
      title={`Processes (${rows.length})`}
      actions={
        <div className={styles.filters}>
          <Button size="sm" variant={filter === 'all' ? 'primary' : 'ghost'} onClick={() => setFilter('all')}>All</Button>
          <Button size="sm" variant={filter === 'suspicious' ? 'primary' : 'ghost'} onClick={() => setFilter('suspicious')}>Suspicious only</Button>
        </div>
      }
    >
      <div className={tableStyles.wrap}>
        <table className={tableStyles.table}>
          <thead>
            <tr>
              <th>PID</th><th>Name</th><th>Score</th><th>Confidence</th>
              <th>Mitigation</th><th>Threads</th><th>Ticks</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <Fragment key={p.pid}>
                <tr className={styles.row} onClick={() => setExpanded(expanded === p.pid ? null : p.pid)}>
                  <td className={tableStyles.mono}>{p.pid}</td>
                  <td>{p.comm}</td>
                  <td><ScoreBar score={p.score} /></td>
                  <td><TierBadge tier={p.confidence} /></td>
                  <td className={styles.mitigation}>{p.mitigation || 'NONE'}</td>
                  <td className={tableStyles.mono}>{p.sched?.thread_count ?? '—'}</td>
                  <td className={tableStyles.mono}>{p.ticks ?? 0}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div className={styles.actions}>
                      <Button size="sm" disabled={busyPid === p.pid} onClick={() => handleRevoke(p.pid)}>Revoke</Button>
                      <Button size="sm" variant="danger" disabled={busyPid === p.pid} onClick={() => handleKill(p.pid)}>Kill</Button>
                    </div>
                  </td>
                </tr>
                {expanded === p.pid && (
                  <tr>
                    <td colSpan={8} className={styles.detailRow}>
                      <div className={styles.reasonsList}>
                        {(p.reasons || []).length === 0 && <span className={styles.noReasons}>No active reasons.</span>}
                        {(p.reasons || []).map((r, i) => <div key={i}>• {r}</div>)}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <div className={tableStyles.empty}>No processes match this filter.</div>}
      </div>
    </Panel>
  );
}
