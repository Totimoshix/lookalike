import { useState } from "react";
import { AnalyzeView } from "./components/AnalyzeView";
import { LookalikeView } from "./components/LookalikeView";

type TabKey = "analyze" | "lookalikes";

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>("analyze");

  return (
    <main className="app-shell">
      <header className="masthead">
        <div className="masthead-brand">
          <div aria-hidden="true" className="brand-mark">
            <span />
            <span />
            <span />
            <span />
          </div>
          <div>
            <p className="eyebrow eyebrow-on-dark">Capstone Domain Guardian</p>
            <h1>Domain Guardian</h1>
            <p className="masthead-subtitle">Lookalike Risk Workbench</p>
          </div>
        </div>
        <p className="masthead-copy">
          Manual-entry phishing triage with weighted scoring, evidence panels, reporting guidance, and lookalike generation.
        </p>
      </header>

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

      {activeTab === "analyze" ? <AnalyzeView /> : <LookalikeView />}
    </main>
  );
}
