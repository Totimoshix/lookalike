import { defineManifest } from "@crxjs/vite-plugin";

const apiBaseUrl = process.env.VITE_API_BASE_URL ?? "http://localhost:3000";
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
