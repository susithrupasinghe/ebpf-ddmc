import { useEffect, useState } from 'react';
import { Panel } from '../components/Panel.jsx';
import { Button } from '../components/Button.jsx';
import styles from './Config.module.css';

const TIER_FIELDS = [
  { key: 'alert_threshold',     label: 'Alert (LOW)' },
  { key: 'throttle_threshold',  label: 'Throttle (MEDIUM)' },
  { key: 'block_threshold',     label: 'Block (HIGH)' },
  { key: 'terminate_threshold', label: 'Terminate (CRITICAL)' },
];

const FLOOR_FIELDS = [
  { key: 'pool_floor',        label: 'Pool-connection floor' },
  { key: 'scratchpad_floor',  label: 'RandomX-scratchpad floor' },
];

const WEIGHT_LABELS = {
  futex_strong:        'Futex ratio ≥ 40%',
  futex_moderate:      'Futex ratio ≥ 20%',
  compute_pure:        'Compute-pure (low I/O, high CPU)',
  thread_full_sat:     'Threads ≥ CPU count',
  thread_partial_sat:  'Threads ≥ 60% of CPU count',
  cpu_high:            'CPU ≥ 85%',
  scratchpad_exact:    'RandomX scratchpad signature',
  huge_pages:          'Huge-page (MAP_HUGETLB) requests',
  cpu_bound_strong:    'Involuntary preemption ≥ 92%',
  cpu_bound_moderate:  'Involuntary preemption ≥ 75%',
  sustained_medium:    'Suspicious ≥ 3 windows (~15s)',
  sustained_high:      'Suspicious ≥ 6 windows (~30s)',
  pool_connection:     'Confirmed stratum pool connection',
};

export function Config() {
  const [detection, setDetection] = useState(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => { load(); }, []);

  async function load() {
    const cfg = await window.eddmc.config();
    setDetection(cfg.detection || {});
  }

  function setField(key, value) {
    setDetection((d) => ({ ...d, [key]: value }));
  }

  function setWeight(key, value) {
    setDetection((d) => ({ ...d, weights: { ...d.weights, [key]: value } }));
  }

  async function handleSave() {
    setSaving(true);
    setMessage(null);
    try {
      const payload = {
        alert_threshold: detection.alert_threshold,
        throttle_threshold: detection.throttle_threshold,
        block_threshold: detection.block_threshold,
        terminate_threshold: detection.terminate_threshold,
        pool_floor: detection.pool_floor,
        scratchpad_floor: detection.scratchpad_floor,
        weights: detection.weights,
      };
      const resp = await window.eddmc.updateDetectionConfig(payload);
      if (resp?.error) {
        setMessage({ ok: false, text: resp.error });
      } else {
        setMessage({ ok: true, text: 'Saved — applied live, no restart needed.' });
        setDetection(resp.detection);
      }
    } catch (e) {
      setMessage({ ok: false, text: String(e) });
    } finally {
      setSaving(false);
    }
  }

  if (!detection) {
    return <Panel title="Detection config"><div className={styles.loading}>Loading…</div></Panel>;
  }

  return (
    <div className={styles.wrap}>
      <Panel
        title="Detection config"
        actions={
          <>
            {message && (
              <span className={message.ok ? styles.msgOk : styles.msgErr}>{message.text}</span>
            )}
            <Button variant="primary" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving…' : 'Save & apply'}
            </Button>
          </>
        }
      >
        <div className={styles.grid}>
          <section className={styles.section}>
            <h3 className={styles.sectionTitle}>Tier thresholds</h3>
            <p className={styles.sectionHint}>Minimum score (0–100) to enter each tier.</p>
            {TIER_FIELDS.map(({ key, label }) => (
              <NumberField key={key} label={label} value={detection[key]} onChange={(v) => setField(key, v)} />
            ))}
          </section>

          <section className={styles.section}>
            <h3 className={styles.sectionTitle}>Hard-evidence floors</h3>
            <p className={styles.sectionHint}>A confirmed signal here overrides a lower weighted-sum score.</p>
            {FLOOR_FIELDS.map(({ key, label }) => (
              <NumberField key={key} label={label} value={detection[key]} onChange={(v) => setField(key, v)} />
            ))}
          </section>
        </div>

        <section className={styles.section}>
          <h3 className={styles.sectionTitle}>Feature weights</h3>
          <p className={styles.sectionHint}>Points added to the suspicion score when each signal fires.</p>
          <div className={styles.weightsGrid}>
            {Object.entries(detection.weights || {}).map(([key, value]) => (
              <NumberField
                key={key}
                label={WEIGHT_LABELS[key] || key}
                value={value}
                onChange={(v) => setWeight(key, v)}
              />
            ))}
          </div>
        </section>
      </Panel>
    </div>
  );
}

function NumberField({ label, value, onChange }) {
  return (
    <label className={styles.field}>
      <span className={styles.fieldLabel}>{label}</span>
      <input
        type="number"
        className={styles.fieldInput}
        value={value ?? ''}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </label>
  );
}
