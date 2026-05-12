import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node"
  },
  resolve: {
    alias: {
      "@capstone/shared": path.resolve(__dirname, "shared/src/index.ts"),
      "@capstone/shared/schema": path.resolve(__dirname, "shared/src/schema.ts"),
      "@capstone/shared/utils": path.resolve(__dirname, "shared/src/utils.ts")
    }
  }
});

