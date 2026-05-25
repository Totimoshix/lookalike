import { useEffect, useState } from "react";
import {
  getApiBaseUrl,
  removeTrustedDomain,
  setApiBaseUrl,
  useExpertMode,
  useRealtimeProtection,
  useTrustedDomains
} from "../lib/storage";

export function OptionsPage() {
  const [expertMode, setExpertMode] = useExpertMode();
  const [realtime, setRealtime] = useRealtimeProtection();
  const [trustedDomains, setTrustedDomains] = useTrustedDomains();
  const [apiBaseUrl, setApiBaseUrlState] = useState<string>("");
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  useEffect(() => {
    getApiBaseUrl().then((value) => setApiBaseUrlState(value ?? ""));
  }, []);

  const handleRemoveTrusted = async (domain: string) => {
    await removeTrustedDomain(domain);
    const next = new Set(trustedDomains);
    next.delete(domain);
    setTrustedDomains(next);
  };

  const handleSaveApiBase = async () => {
    await setApiBaseUrl(apiBaseUrl.trim().length > 0 ? apiBaseUrl.trim() : null);
    setSavedMessage("Saved");
    setTimeout(() => setSavedMessage(null), 1500);
  };

  return (
    <main className="options-shell">
      <header className="options-head">
        <div className="options-head-brand">
          <span aria-hidden="true">🛡</span>
          <h1>Domain Guardian Settings</h1>
        </div>
      </header>

      <section className="options-card">
        <h2>Real-time protection</h2>
        <p className="options-help">
          When on, Domain Guardian quietly checks the sites you visit and shows a warning page before any
          page flagged as a likely lookalike loads.
        </p>
        <label className="options-toggle">
          <input
            type="checkbox"
            checked={realtime}
            onChange={(event) => setRealtime(event.target.checked)}
          />
          <span>{realtime ? "Enabled" : "Disabled"}</span>
        </label>
        <p className="options-note">
          Warnings fire only for High, Critical, or Malicious verdicts. Popular sites bundled in the
          allowlist are skipped automatically.
        </p>
      </section>

      <section className="options-card">
        <h2>Expert mode</h2>
        <p className="options-help">
          Show the full analyst breakdown by default — score card, evidence table, eight risk categories,
          reporting contacts, JSON export, and the lookalike generator.
        </p>
        <label className="options-toggle">
          <input
            type="checkbox"
            checked={expertMode}
            onChange={(event) => setExpertMode(event.target.checked)}
          />
          <span>{expertMode ? "Enabled" : "Disabled"}</span>
        </label>
      </section>

      <section className="options-card">
        <h2>Trusted sites</h2>
        <p className="options-help">
          Domains you've marked as trusted will never trigger a warning. Remove an entry below to revoke
          that trust.
        </p>
        {trustedDomains.size === 0 ? (
          <p className="options-empty">No trusted sites yet.</p>
        ) : (
          <ul className="options-list">
            {Array.from(trustedDomains)
              .sort()
              .map((domain) => (
                <li key={domain}>
                  <span>{domain}</span>
                  <button className="link-button" onClick={() => handleRemoveTrusted(domain)} type="button">
                    Remove
                  </button>
                </li>
              ))}
          </ul>
        )}
      </section>

      <section className="options-card">
        <h2>API endpoint</h2>
        <p className="options-help">
          Override the backend the extension talks to. Leave empty to use the default
          (<code>http://127.0.0.1:3000</code> for local development).
        </p>
        <label className="input-block">
          <span>API base URL</span>
          <input
            autoComplete="off"
            onChange={(event) => setApiBaseUrlState(event.target.value)}
            placeholder="https://api.example.com"
            value={apiBaseUrl}
          />
        </label>
        <div className="action-row">
          <button className="primary-button" onClick={handleSaveApiBase} type="button">
            Save
          </button>
          {savedMessage ? <span className="options-saved">{savedMessage}</span> : null}
        </div>
      </section>
    </main>
  );
}
