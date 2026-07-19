import { useState } from 'react';
import { Sidebar } from './components/Sidebar.jsx';
import { usePolling } from './hooks/usePolling.js';
import { Dashboard } from './views/Dashboard.jsx';
import { Processes } from './views/Processes.jsx';
import { Alerts } from './views/Alerts.jsx';
import { Config } from './views/Config.jsx';
import { Allowlist } from './views/Allowlist.jsx';
import styles from './App.module.css';

const VIEWS = {
  dashboard: Dashboard,
  processes: Processes,
  alerts: Alerts,
  config: Config,
  allowlist: Allowlist,
};

export default function App() {
  const [active, setActive] = useState('dashboard');
  const status = usePolling(() => window.eddmc.status(), 2000, { status: 'offline', tracked: 0, uptime: 0 });
  const alerts = usePolling(() => window.eddmc.alerts(), 3000, []);

  const ActiveView = VIEWS[active];

  return (
    <div className={styles.shell}>
      <Sidebar
        active={active}
        onNavigate={setActive}
        status={status}
        alertCount={alerts?.length || 0}
      />
      <main className={styles.main}>
        <ActiveView status={status} alerts={alerts} />
      </main>
    </div>
  );
}
