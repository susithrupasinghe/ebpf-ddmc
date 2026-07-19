import styles from './Badge.module.css';

// Confidence tiers map to the palette's fixed status roles. NONE/LOW aren't
// alarm states, so they get neutral/informational treatment rather than
// borrowing a warning-ladder color that would misrepresent them.
const TIER_CLASS = {
  NONE:     'muted',
  LOW:      'info',
  MEDIUM:   'warning',
  HIGH:     'serious',
  CRITICAL: 'critical',
};

export function TierBadge({ tier }) {
  const cls = TIER_CLASS[tier] || 'muted';
  return <span className={`${styles.badge} ${styles[cls]}`}>{tier || 'NONE'}</span>;
}

const STATUS_CLASS = {
  pending:   'warning',
  confirmed: 'good',
  online:    'good',
  offline:   'critical',
  running:   'good',
};

export function StatusBadge({ status, children }) {
  const cls = STATUS_CLASS[status] || 'muted';
  return <span className={`${styles.badge} ${styles[cls]}`}>{children || status}</span>;
}
