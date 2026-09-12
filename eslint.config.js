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
      // `^_` also covers destructuring used to omit a property, which is the
      // cleanest way to drop a field from an object without mutating it.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
      'no-empty': ['error', { allowEmptyCatch: false }],
      eqeqeq: ['error', 'smart'],
    },
  },
  {
    files: ['src/util/json.ts', 'src/collectors/dependencies.ts', 'src/util/yaml.ts'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
);
