import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["src/api/schema.d.ts", "test-results", "playwright-report"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  reactHooks.configs.flat["recommended-latest"],
  jsxA11y.flatConfigs.strict,
  {
    languageOptions: { globals: { ...globals.browser } },
  },
  {
    files: ["*.config.{js,ts}", "scripts/**", "e2e/**"],
    languageOptions: { globals: { ...globals.node } },
  },
);
