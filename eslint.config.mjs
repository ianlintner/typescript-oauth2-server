import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['node_modules/**', '.worktrees/**', 'dist/**', 'coverage/**'] },
  ...tseslint.configs.recommended,
);
