import { usePolling } from '../hooks/usePolling.js';
import { StatCard } from '../components/StatCard.jsx';
import { Panel } from '../components/Panel.jsx';
import { TierBadge } from '../components/Badge.jsx';
import { ScoreBar } from '../components/ScoreBar.jsx';
import tableStyles from '../components/Table.module.css';
import styles from './Dashboard.module.css';

export function Dashboard({ alerts }) {
  const processes = usePolling(() => window.eddmc.processes(), 2000, []);

  const suspicious = processes.filter((p) => (p.confidence || 'NONE') !== 'NONE');
  const highCritical = processes.filter((p) => ['HIGH', 'CRITICAL'].includes(p.confidence));
  const top = [...suspicious].sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 8);
  const recentAlerts = [...(alerts || [])].reverse().slice(0, 5);

  return (
    <div className={styles.wrap}>
      <div className={styles.stats}>
        <StatCard label="Tracked processes" value={processes.length} />
        <StatCard label="Suspicious" value={suspicious.length} tone={suspicious.length ? 'warning' : 'neutral'} />
        <StatCard label="High / Critical" value={highCritical.length} tone={highCritical.length ? 'critical' : 'neutral'} />
        <StatCard label="Total alerts" value={(alerts || []).length} />
      </div>

      <Panel title="Top suspicious processes">
        <div className={tableStyles.wrap}>
          <table className={tableStyles.table}>
            <thead>
              <tr>
                <th>PID</th><th>Name</th><th>Score</th><th>Confidence</th><th>Mitigation</th><th>Reasons</th>
              </tr>
            </thead>
            <tbody>
              {top.map((p) => (
                <tr key={p.pid}>
                  <td className={tableStyles.mono}>{p.pid}</td>
                  <td>{p.comm}</td>
                  <td><ScoreBar score={p.score} /></td>
                  <td><TierBadge tier={p.confidence} /></td>
                  <td className={styles.mitigation}>{p.mitigation || 'NONE'}</td>
                  <td className={styles.reasons}>{(p.reasons || [])[0] || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {top.length === 0 && <div className={tableStyles.empty}>No suspicious processes right now.</div>}
        </div>
      </Panel>

      <Panel title="Recent alerts">
        <div className={styles.alertList}>
          {recentAlerts.map((a, i) => (
            <div key={i} className={styles.alertItem} data-tier={a.confidence}>
              <div className={styles.alertHead}>
                <TierBadge tier={a.confidence} />
                <span className={styles.alertComm}>{a.comm}</span>
                <span className={styles.alertAction}>{a.action}</span>
                <span className={styles.alertTime}>{formatTime(a.timestamp)}</span>
              </div>
            </div>
          ))}
          {recentAlerts.length === 0 && <div className={tableStyles.empty}>No alerts yet.</div>}
        </div>
      </Panel>
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleTimeString();
}
