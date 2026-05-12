import { defineManifest } from "@crxjs/vite-plugin";

const apiBaseUrl = process.env.VITE_API_BASE_URL ?? "http://localhost:3000";
const apiOrigin = new URL(apiBaseUrl).origin;
const hostPermissions = Array.from(
  new Set([`${apiOrigin}/*`, "http://localhost:3000/*", "http://127.0.0.1:3000/*"])
);

export default defineManifest({
  manifest_version: 3,
  name: "Capstone Domain Guardian",
  version: "0.1.0",
  description: "Manual-entry lookalike domain detection with analyst-grade evidence and JSON export.",
  action: {
    default_title: "Capstone Domain Guardian",
    default_popup: "index.html"
  },
  host_permissions: hostPermissions
});
