module.exports = {
  root: true,
  env: {
    es2021: true,
    node: true,
  },
  plugins: ["eslint-plugin", "@typescript-eslint"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended",
  ],
  parser: "@typescript-eslint/parser",
  rules: {},
};
