import { useEffect, useState, type FormEvent } from "react";

type UrlInputCardProps = {
  expertMode: boolean;
  isLoading: boolean;
  onSubmit: (url: string, brandOverride: string | undefined) => void;
};

async function readActiveTabUrl(): Promise<string | null> {
  if (typeof chrome === "undefined" || !chrome.tabs || typeof chrome.tabs.query !== "function") {
    return null;
  }
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tabUrl = tabs[0]?.url;
    if (!tabUrl) return null;
    if (!/^https?:\/\//i.test(tabUrl)) return null;
    return tabUrl;
  } catch {
    return null;
  }
}

export function UrlInputCard({ expertMode, isLoading, onSubmit }: UrlInputCardProps) {
  const [url, setUrl] = useState("");
  const [brandOverride, setBrandOverride] = useState("");
  const [currentTabUrl, setCurrentTabUrl] = useState<string | null>(null);

  useEffect(() => {
    readActiveTabUrl().then(setCurrentTabUrl);
  }, []);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (url.trim().length === 0) return;
    onSubmit(url.trim(), expertMode && brandOverride.trim().length > 0 ? brandOverride.trim() : undefined);
  };

  const useCurrentTab = () => {
    if (currentTabUrl) setUrl(currentTabUrl);
  };

  return (
    <form className="input-card" onSubmit={handleSubmit}>
      <label className="input-block">
        <span>Check a link</span>
        <input
          autoComplete="off"
          inputMode="url"
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://example.com or example.com"
          value={url}
        />
      </label>
      {expertMode ? (
        <label className="input-block">
          <span>Brand override (optional)</span>
          <input
            autoComplete="off"
            onChange={(event) => setBrandOverride(event.target.value)}
            placeholder="Amazon or amazon.com"
            value={brandOverride}
          />
        </label>
      ) : null}
      <div className="action-row">
        <button className="primary-button" disabled={isLoading || url.trim().length === 0} type="submit">
          {isLoading ? (
            <>
              <span aria-hidden="true" className="spinner" /> Checking…
            </>
          ) : (
            "Check"
          )}
        </button>
        {currentTabUrl ? (
          <button className="link-button" onClick={useCurrentTab} type="button">
            Use current tab
          </button>
        ) : null}
      </div>
    </form>
  );
}
