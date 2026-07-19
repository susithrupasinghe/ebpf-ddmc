import styles from './Sidebar.module.css';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { id: 'processes', label: 'Processes', icon: ProcessesIcon },
  { id: 'alerts',    label: 'Alerts',    icon: AlertsIcon },
  { id: 'allowlist', label: 'Allowlist', icon: ShieldIcon },
  { id: 'config',    label: 'Config',    icon: ConfigIcon },
];

export function Sidebar({ active, onNavigate, status, alertCount }) {
  const online = status?.status === 'running';
  return (
    <aside className={styles.sidebar}>
      <div className={styles.brand}>
        <div className={styles.logo}>E</div>
        <div>
          <div className={styles.brandName}>EDDMC</div>
          <div className={styles.brandSub}>Cryptojacking Detection</div>
        </div>
      </div>

      <nav className={styles.nav}>
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`${styles.navItem} ${active === id ? styles.navItemActive : ''}`}
            onClick={() => onNavigate(id)}
          >
            <Icon />
            <span>{label}</span>
            {id === 'alerts' && alertCount > 0 && (
              <span className={styles.navBadge}>{alertCount > 99 ? '99+' : alertCount}</span>
            )}
          </button>
        ))}
      </nav>

      <div className={styles.footer}>
        <div className={styles.statusRow}>
          <span className={`${styles.dot} ${online ? styles.dotOnline : styles.dotOffline}`} />
          <span className={styles.statusText}>{online ? 'Daemon online' : 'Daemon offline'}</span>
        </div>
        {online && (
          <div className={styles.statusMeta}>
            {status.tracked} tracked · {formatUptime(status.uptime)}
          </div>
        )}
      </div>
    </aside>
  );
}

function formatUptime(seconds = 0) {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function DashboardIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="1.5" y="1.5" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
      <rect x="8.5" y="1.5" width="6" height="4" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
      <rect x="8.5" y="7.5" width="6" height="7" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
      <rect x="1.5" y="9.5" width="6" height="5" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}
function ProcessesIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M2 4h12M2 8h12M2 12h8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}
function AlertsIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M8 1.5 14.5 13h-13L8 1.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M8 6.5v3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="8" cy="11.2" r="0.9" fill="currentColor" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M8 1.5 13.5 3.5v4c0 4-2.4 6.4-5.5 7.5-3.1-1.1-5.5-3.5-5.5-7.5v-4L8 1.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M5.7 8 7.3 9.6 10.5 6.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function ConfigIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="2.2" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M8 1.8v1.6M8 12.6v1.6M14.2 8h-1.6M3.4 8H1.8M12.2 3.8l-1.1 1.1M4.9 11.1l-1.1 1.1M12.2 12.2l-1.1-1.1M4.9 4.9 3.8 3.8"
        stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"
      />
    </svg>
  );
}
