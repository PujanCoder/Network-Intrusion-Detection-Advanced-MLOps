import { HashRouter, Route, Routes } from "react-router-dom";

import { Layout } from "./components/Layout";
import { useLiveStream } from "./hooks/useLiveStream";
import { LiveContext } from "./lib/LiveContext";
import { AnalyticsPage } from "./pages/Analytics";
import { AttacksPage } from "./pages/Attacks";
import { ExplorerPage } from "./pages/Explorer";
import { ModelPage } from "./pages/Model";
import { OverviewPage } from "./pages/Overview";
import { SensorsPage } from "./pages/Sensors";
import { StreamPage } from "./pages/Stream";

export default function App() {
  const live = useLiveStream();

  return (
    <LiveContext.Provider value={live}>
      <HashRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/stream" element={<StreamPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/attacks" element={<AttacksPage />} />
            <Route path="/model" element={<ModelPage />} />
            <Route path="/explorer" element={<ExplorerPage />} />
            <Route path="/sensors" element={<SensorsPage />} />
            <Route path="*" element={<OverviewPage />} />
          </Routes>
        </Layout>
      </HashRouter>
    </LiveContext.Provider>
  );
}
