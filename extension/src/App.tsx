import { useState } from "react";
import { AppHeader } from "./components/AppHeader";
import { AnalyzeView } from "./components/AnalyzeView";
import { LookalikeView } from "./components/LookalikeView";
import { useExpertMode } from "./lib/storage";

type TabKey = "analyze" | "lookalikes";

export default function App() {
  const [expertMode, setExpertMode] = useExpertMode();
  const [activeTab, setActiveTab] = useState<TabKey>("analyze");

  return (
    <main className="app-shell">
      <AppHeader expertMode={expertMode} onExpertModeChange={setExpertMode} />

      {expertMode ? (
        <nav className="tab-strip" aria-label="Views">
          <button
            className={activeTab === "analyze" ? "tab-button active" : "tab-button"}
            onClick={() => setActiveTab("analyze")}
            type="button"
          >
            Analyze
          </button>
          <button
            className={activeTab === "lookalikes" ? "tab-button active" : "tab-button"}
            onClick={() => setActiveTab("lookalikes")}
            type="button"
          >
            Generate Lookalikes
          </button>
        </nav>
      ) : null}

      {expertMode && activeTab === "lookalikes" ? <LookalikeView /> : <AnalyzeView expertMode={expertMode} />}
    </main>
  );
}
