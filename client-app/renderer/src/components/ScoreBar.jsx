import styles from './ScoreBar.module.css';

// Sequential magnitude encoding: one hue (blue), light -> dark as score rises,
// per the palette's sequential-hue rule. Independent of the tier badge, which
// carries the categorical status meaning.
const STEPS = [
  { max: 20,  color: '#cde2fb' },
  { max: 40,  color: '#86b6ef' },
  { max: 60,  color: '#3987e5' },
  { max: 80,  color: '#1c5cab' },
  { max: 101, color: '#0d366b' },
];

function colorFor(score) {
  return (STEPS.find((s) => score < s.max) || STEPS[STEPS.length - 1]).color;
}

export function ScoreBar({ score = 0 }) {
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div className={styles.wrap}>
      <div className={styles.track}>
        <div
          className={styles.fill}
          style={{ width: `${pct}%`, background: colorFor(pct) }}
        />
      </div>
      <span className={styles.value}>{pct.toFixed(0)}</span>
    </div>
  );
}
