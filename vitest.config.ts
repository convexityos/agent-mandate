import { configDefaults, defineConfig } from 'vitest/config';

/**
 * The only thing this configures is what *not* to collect.
 *
 * Two directories in a working copy of this project contain a second, stale copy
 * of the test suite:
 *
 *   - `dist/`, whenever `npm run build` has been run — which `npm run vectors`
 *     and `npm run am` both do.
 *   - `.claude/worktrees/`, where the harness checks out isolated copies. Git
 *     excludes those, so they never show up in `git status` and there is nothing
 *     to notice.
 *
 * Collected, they double the run and — worse — report on a snapshot of the code
 * rather than on the code. A suite that passes because an old copy of it passed
 * is the failure mode this file exists to prevent, and it is silent.
 */
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, '**/dist/**', '**/.claude/**'],
  },
});
