import { handleNavigation } from "./navigationGuard";

chrome.runtime.onInstalled.addListener(() => {
  console.log("[DomainGuardian] service worker installed");
});

chrome.webNavigation.onCommitted.addListener(
  (details) => {
    void handleNavigation(details);
  },
  { url: [{ schemes: ["http", "https"] }] }
);
