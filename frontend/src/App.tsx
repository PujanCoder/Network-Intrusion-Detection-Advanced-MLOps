import { HashRouter, Route, Routes } from "react-router-dom";

import { ErrorBoundary } from "./components/ErrorBoundary";
import { Layout } from "./components/Layout";
import { useLiveStream } from "./hooks/useLiveStream";
import { AuthProvider, useAuth } from "./lib/auth";
import { LiveContext } from "./lib/LiveContext";
import { AnalyticsPage } from "./pages/Analytics";
import { AttacksPage } from "./pages/Attacks";
import { ExplorerPage } from "./pages/Explorer";
import { HealthPage } from "./pages/Health";
import { LoginPage, UnconfiguredScreen } from "./pages/Login";
import { ModelPage } from "./pages/Model";
import { OverviewPage } from "./pages/Overview";
import { SensorsPage } from "./pages/Sensors";
import { StreamPage } from "./pages/Stream";

function Dashboard() {
  const live = useLiveStream();
  return (
    <LiveContext.Provider value={live}>
      <HashRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/live" element={<StreamPage />} />
            <Route path="/threats" element={<AttacksPage />} />
            <Route path="/investigate" element={<ExplorerPage />} />
            <Route path="/sensors" element={<SensorsPage />} />
            <Route path="/models" element={<ModelPage />} />
            <Route path="/system" element={<HealthPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="*" element={<OverviewPage />} />
          </Routes>
        </Layout>
      </HashRouter>
    </LiveContext.Provider>
  );
}

function Gate() {
  const auth = useAuth();
  if (auth.status === "loading") {
    return (
      <div className="auth-screen">
        <div className="loading">Connecting to the platform…</div>
      </div>
    );
  }
  if (auth.status === "unconfigured") return <UnconfiguredScreen />;
  if (auth.status === "anonymous") return <LoginPage />;
  return <Dashboard />;
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </ErrorBoundary>
  );
}
