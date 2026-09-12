import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'test/fixtures/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // This tool inspects untrusted repositories; explicit `any` at trust
      // boundaries (JSON from `npm audit`, etc.) is intentional and narrowed
      // immediately afterwards. Everything else must be typed.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-empty': ['error', { allowEmptyCatch: false }],
      eqeqeq: ['error', 'smart'],
    },
  },
  {
    files: ['src/util/json.ts', 'src/collectors/dependencies.ts', 'src/util/yaml.ts'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
);
