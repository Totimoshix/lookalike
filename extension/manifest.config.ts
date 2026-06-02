import { defineManifest } from "@crxjs/vite-plugin";

// Defaults to the deployed prod API so the built extension is granted access
// to the AWS origin without needing VITE_API_BASE_URL at build time. Localhost
// origins stay in the list so local dev still works after a runtime override.
const apiBaseUrl =
  process.env.VITE_API_BASE_URL ?? "https://x7g9yk2qm5.execute-api.ca-central-1.amazonaws.com/prod";
const apiOrigin = new URL(apiBaseUrl).origin;
const apiHostPermissions = Array.from(
  new Set([`${apiOrigin}/*`, "http://localhost:3000/*", "http://127.0.0.1:3000/*"])
);

export default defineManifest({
  manifest_version: 3,
  name: "Capstone Domain Guardian",
  version: "0.1.0",
  description:
    "Lookalike-domain detection with on-demand analysis and optional real-time warnings while you browse.",
  action: {
    default_title: "Capstone Domain Guardian",
    default_popup: "index.html"
  },
  options_ui: {
    page: "options.html",
    open_in_tab: true
  },
  background: {
    service_worker: "src/background/index.ts",
    type: "module"
  },
  permissions: ["tabs", "webNavigation", "storage", "activeTab"],
  host_permissions: [...apiHostPermissions, "<all_urls>"],
  web_accessible_resources: [
    {
      resources: ["warning.html"],
      matches: ["<all_urls>"]
    }
  ]
});
