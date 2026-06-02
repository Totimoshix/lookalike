import { useRealtimeProtection } from "../lib/storage";

type AppHeaderProps = {
  expertMode: boolean;
  onExpertModeChange: (next: boolean) => void;
};

function openOptions() {
  if (typeof chrome !== "undefined" && chrome.runtime && typeof chrome.runtime.getURL === "function") {
    const optionsUrl = chrome.runtime.getURL("options.html");
    if (typeof window !== "undefined") {
      window.open(optionsUrl, "_blank");
    }
  }
}

export function AppHeader({ expertMode, onExpertModeChange }: AppHeaderProps) {
  const [realtime, setRealtime] = useRealtimeProtection();
  return (
    <header className="app-header">
      <div className="app-header-brand">
        <span aria-hidden="true" className="app-header-logo">🛡</span>
        <span className="app-header-title">Domain Guardian</span>
      </div>
      <div className="app-header-actions">
        <label className="expert-toggle" title="Warn me before dangerous sites load">
          <input
            type="checkbox"
            checked={realtime}
            onChange={(event) => setRealtime(event.target.checked)}
          />
          <span className="expert-toggle-track">
            <span className="expert-toggle-thumb" />
          </span>
          <span className="expert-toggle-label">Live</span>
        </label>
        <label className="expert-toggle">
          <input
            type="checkbox"
            checked={expertMode}
            onChange={(event) => onExpertModeChange(event.target.checked)}
          />
          <span className="expert-toggle-track">
            <span className="expert-toggle-thumb" />
          </span>
          <span className="expert-toggle-label">Expert</span>
        </label>
        <button
          aria-label="Settings"
          className="icon-button"
          onClick={openOptions}
          type="button"
        >
          ⚙
        </button>
      </div>
    </header>
  );
}
