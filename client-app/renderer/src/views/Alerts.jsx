import { TierBadge } from '../components/Badge.jsx';
import { Panel } from '../components/Panel.jsx';
import tableStyles from '../components/Table.module.css';
import styles from './Alerts.module.css';

export function Alerts({ alerts }) {
  const list = [...(alerts || [])].reverse();

  return (
    <Panel title={`Alerts (${list.length})`}>
      <div className={styles.list}>
        {list.map((a, i) => (
          <div key={i} className={styles.item} data-tier={a.confidence}>
            <div className={styles.head}>
              <TierBadge tier={a.confidence} />
              <span className={styles.comm}>{a.comm}</span>
              <span className={styles.pid}>pid {a.pid}</span>
              <span className={styles.action}>{a.action}</span>
              {a.dry_run && <span className={styles.dryRun}>DRY-RUN</span>}
              <span className={styles.time}>{formatTime(a.timestamp)}</span>
            </div>
            {(a.reasons || []).length > 0 && (
              <ul className={styles.reasons}>
                {a.reasons.map((r, j) => <li key={j}>{r}</li>)}
              </ul>
            )}
          </div>
        ))}
        {list.length === 0 && <div className={tableStyles.empty}>No alerts yet.</div>}
      </div>
    </Panel>
  );
}

function formatTime(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleString();
}
