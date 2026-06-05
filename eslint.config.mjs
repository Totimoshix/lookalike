// Flat ESLint config. Conservative ruleset: catch genuinely-likely bugs
// (unused vars, unsafe constructs) without drowning the codebase in style
// noise. TypeScript already handles undefined-reference checking, so the base
// `no-undef` rule is disabled. The CI lint job is advisory (continue-on-error)
// while the codebase adopts this.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/cdk.out/**",
      "**/.claude/**",
      "**/*.generated.ts",
      "**/*.config.*",
      "scripts/*.mjs",
      "eslint.config.mjs"
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "no-undef": "off",
      "no-console": "off",
      "no-empty": ["warn", { allowEmptyCatch: true }],
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }
      ]
    }
  }
);
