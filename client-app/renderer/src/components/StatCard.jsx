import styles from './StatCard.module.css';

const TONE_VAR = {
  neutral:  '--text-primary',
  good:     '--status-good',
  warning:  '--status-warning',
  serious:  '--status-serious',
  critical: '--status-critical',
};

export function StatCard({ label, value, tone = 'neutral', hint }) {
  return (
    <div className={styles.card}>
      <div className={styles.label}>{label}</div>
      <div className={styles.value} style={{ color: `var(${TONE_VAR[tone] || TONE_VAR.neutral})` }}>
        {value}
      </div>
      {hint && <div className={styles.hint}>{hint}</div>}
    </div>
  );
}
