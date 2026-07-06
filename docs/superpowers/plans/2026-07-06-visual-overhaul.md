# Visual Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the desktop app into a dark-default (with light toggle) identity using a UniFi-blue accent, the Inter font, and a semantic design-token system, without changing any behavior.

**Architecture:** Define all colors as CSS custom properties in `src/app.css` (dark on `:root`, light under `:root[data-theme="light"]`), map them into Tailwind v4 via `@theme` so components use semantic utilities (`bg-surface-1`, `text-fg`, `bg-accent`, `bg-sev-high-tint`, …). A persisted `theme` store toggles `data-theme` on `<html>`; an inline snippet in `app.html` applies it before first paint. Then each screen swaps its hardcoded Tailwind color classes for the semantic ones.

**Tech Stack:** SvelteKit (Svelte 5 runes), Tailwind v4 (`@theme` in `app.css`), `@fontsource-variable/inter`, `svelte/store`.

## Global Constraints

- Pure visual change. Do NOT edit `src/audit/**`, `src/wizard/*.ts`, `src/db/**`, or `src-tauri/**` behavior. Only styling/markup in Svelte components + `app.css` + `app.html` + the theme store.
- Dark is the default theme; light is a toggle. Every color must come from a token so both themes work. The test: "if the background flipped, would this still be readable?"
- Exact token values are in `docs/superpowers/specs/2026-07-06-visual-overhaul-design.md` and reproduced in Task 1. The reference look is `src/routes/design-preview/+page.svelte`.
- No unit tests for components. Gate every task on `npm run typecheck` and `npm run build` (both must pass) plus a visual check in `npm run dev` in BOTH themes. The existing Vitest suite (`npm test`) covers audit-core logic, is unaffected, and must stay green.
- Accent is UniFi blue: `#3b82f6` (dark) / `#1d6fe0` (light).
- Delete the throwaway `src/routes/design-preview/` route before the branch merges (Task 8).
- Commit messages: no Claude attribution / Co-Authored-By trailers.

## The class-mapping table (used by every screen task)

Replace hardcoded Tailwind color classes with these semantic utilities. This is the authoritative transform:

| Old (hardcoded) | New (token utility) |
| --- | --- |
| `bg-white`, card backgrounds | `bg-surface-1` |
| `bg-gray-50` (page/subtle areas) | `bg-surface-0` (page) or `bg-surface-2` (inset) |
| `bg-gray-100` | `bg-surface-2` |
| `border`, `border-gray-200`, `border-gray-100` | `border-line` |
| `border-gray-300` (emphasis) | `border-line-strong` |
| `text-gray-900`, `text-gray-800` | `text-fg` |
| `text-gray-700`, `text-gray-600` | `text-fg-muted` |
| `text-gray-500`, `text-gray-400` | `text-fg-subtle` |
| `bg-blue-600` (primary button) | `bg-accent text-on-accent` |
| `hover:bg-blue-700` | `hover:bg-accent-hover` |
| `text-blue-600`, `text-blue-700` (links/accents) | `text-accent` |
| `bg-blue-50`, `bg-blue-100` | `bg-accent-tint` |
| `border-blue-600` | `border-accent` |
| `bg-red-50` / `text-red-600` / `text-red-700` | `bg-sev-high-tint` / `text-sev-high` |
| `bg-amber-50` / `text-amber-700` | `bg-sev-warn-tint` / `text-sev-warn` |
| `bg-green-50` / `text-green-600` / `text-green-700` | `bg-sev-ok-tint` / `text-sev-ok` |
| `bg-gray-800` (dark chip on light) | `bg-accent` or `bg-surface-2` per context |

To find every class to replace in a file:
```bash
grep -noE "(bg|text|border|hover:bg|hover:border)-(gray|blue|red|green|amber|slate|indigo)-[0-9]+|\bborder\b(?!-)" <file>
```

---

### Task 1: Design tokens, Inter, theme system, and app shell

**Files:**
- Modify: `src/app.css`, `src/app.html`, `src/routes/+layout.svelte`, `package.json` (dependency)
- Create: `src/lib/stores/theme.ts`

**Interfaces:**
- Produces: semantic Tailwind utilities (`bg-surface-{0,1,2}`, `border-line`, `border-line-strong`, `text-fg`, `text-fg-muted`, `text-fg-subtle`, `bg-accent`, `hover:bg-accent-hover`, `text-accent`, `bg-accent-tint`, `text-on-accent`, `border-accent`, `bg-sev-{high,warn,ok,info}-tint`, `text-sev-{high,warn,ok,info}`), the `--font-sans` (Inter) family, and:
  - `theme` — a `Writable<'dark' | 'light'>` store (from `src/lib/stores/theme.ts`)
  - `toggleTheme(): void`, `setTheme(t: 'dark' | 'light'): void`

- [ ] **Step 1: Add the Inter font package**

Run: `npm install @fontsource-variable/inter`
Expected: `package.json` gains `@fontsource-variable/inter`.

- [ ] **Step 2: Write `src/app.css` with tokens + @theme + Inter**

```css
@import "tailwindcss";
@import "@fontsource-variable/inter";

:root {
  color-scheme: dark;
  --surface-0: #0e1116; --surface-1: #161b22; --surface-2: #1c222b;
  --line: #232a34; --line-strong: #2f3742;
  --fg: #e6eaf0; --fg-muted: #9aa5b4; --fg-subtle: #6b7684;
  --accent: #3b82f6; --accent-hover: #2f74e6; --accent-tint: #16233b; --on-accent: #ffffff;
  --sev-high: #f2555a; --sev-high-tint: #241417;
  --sev-warn: #e0a13a; --sev-warn-tint: #241d10;
  --sev-ok: #34d399; --sev-ok-tint: #10251d;
  --sev-info: #5b9bf6; --sev-info-tint: #131f38;
}
:root[data-theme="light"] {
  color-scheme: light;
  --surface-0: #f6f7f9; --surface-1: #ffffff; --surface-2: #ffffff;
  --line: #e5e7eb; --line-strong: #d1d5db;
  --fg: #111827; --fg-muted: #4b5563; --fg-subtle: #9ca3af;
  --accent: #1d6fe0; --accent-hover: #1a63c9; --accent-tint: #e8f1fe; --on-accent: #ffffff;
  --sev-high: #dc2626; --sev-high-tint: #fef2f2;
  --sev-warn: #b45309; --sev-warn-tint: #fffbeb;
  --sev-ok: #059669; --sev-ok-tint: #ecfdf5;
  --sev-info: #2563eb; --sev-info-tint: #eff6ff;
}
html { background: var(--surface-0); }

@theme {
  --color-surface-0: var(--surface-0);
  --color-surface-1: var(--surface-1);
  --color-surface-2: var(--surface-2);
  --color-line: var(--line);
  --color-line-strong: var(--line-strong);
  --color-fg: var(--fg);
  --color-fg-muted: var(--fg-muted);
  --color-fg-subtle: var(--fg-subtle);
  --color-accent: var(--accent);
  --color-accent-hover: var(--accent-hover);
  --color-accent-tint: var(--accent-tint);
  --color-on-accent: var(--on-accent);
  --color-sev-high: var(--sev-high);
  --color-sev-high-tint: var(--sev-high-tint);
  --color-sev-warn: var(--sev-warn);
  --color-sev-warn-tint: var(--sev-warn-tint);
  --color-sev-ok: var(--sev-ok);
  --color-sev-ok-tint: var(--sev-ok-tint);
  --color-sev-info: var(--sev-info);
  --color-sev-info-tint: var(--sev-info-tint);
  --font-sans: "Inter Variable", system-ui, -apple-system, "Segoe UI", sans-serif;
}

body { background: var(--surface-0); color: var(--fg); font-family: var(--font-sans); }
```

- [ ] **Step 3: Add the no-flash theme snippet to `src/app.html`**

Insert this in `<head>`, immediately before `%sveltekit.head%`:

```html
    <script>
      try {
        var t = localStorage.getItem("theme");
        if (t !== "light" && t !== "dark")
          t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", t);
      } catch (e) {
        document.documentElement.setAttribute("data-theme", "dark");
      }
    </script>
```

- [ ] **Step 4: Write `src/lib/stores/theme.ts`**

```ts
import { writable } from 'svelte/store';

export type Theme = 'dark' | 'light';

function initial(): Theme {
  if (typeof document !== 'undefined') {
    const attr = document.documentElement.getAttribute('data-theme');
    if (attr === 'light' || attr === 'dark') return attr;
  }
  return 'dark';
}

export const theme = writable<Theme>(initial());

export function setTheme(t: Theme): void {
  theme.set(t);
}

export function toggleTheme(): void {
  theme.update((t) => (t === 'dark' ? 'light' : 'dark'));
}

theme.subscribe((t) => {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('theme', t); } catch { /* ignore */ }
});
```

- [ ] **Step 5: Restyle `src/routes/+layout.svelte` (nav + footer + theme toggle)**

Apply the mapping table to the nav, and add the toggle to the footer. Key changes: the nav wrapper uses `bg-surface-0 border-line`; active tab uses `border-accent text-accent`, inactive `text-fg-subtle`. The footer gains a theme toggle button next to the version and "Check for updates". Add to the `<script>`:

```ts
  import { theme, toggleTheme } from '../lib/stores/theme.js';
```

Footer toggle markup (place inside the existing `<footer>`, after the "Check for updates" button):

```svelte
    <button class="text-fg-subtle hover:text-fg" onclick={toggleTheme} aria-label="Toggle light and dark theme">
      {$theme === 'dark' ? '☾ Dark' : '☀ Light'}
    </button>
```

Replace the nav's hardcoded classes per the mapping table (e.g. `border-gray-200`→`border-line`, `bg-white`→`bg-surface-0`, active `border-blue-600 text-blue-700`→`border-accent text-accent`, inactive `text-gray-500 hover:text-gray-700`→`text-fg-subtle hover:text-fg`).

- [ ] **Step 6: Verify foundation (both themes)**

Run: `npm run typecheck && npm run build`
Expected: both pass.
Then: `npm run dev`, open `http://localhost:5173/`, confirm the page is dark, the nav/footer are styled, and the footer toggle switches the whole app to light and back (persisted across reload).

- [ ] **Step 7: Commit**

```bash
git add src/app.css src/app.html src/lib/stores/theme.ts src/routes/+layout.svelte package.json package-lock.json
git commit -m "feat(ui): design tokens, Inter font, dark/light theme system + shell"
```

---

### Task 2: Home screen (`/`)

**Files:** Modify `src/routes/+page.svelte`
**Interfaces:** Consumes the Task 1 utilities.

- [ ] **Step 1: List the classes to replace**

Run: `grep -noE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes/+page.svelte`
Expected: prints the hardcoded classes (trust chips `bg-gray-100`, start cards `border-blue-600`/`bg-blue-50`/`bg-blue-100`/`text-blue-700`, `hover:bg-blue-50`/`hover:bg-gray-50`, recent-audit chips `text-blue-700 bg-blue-50`, muted text `text-gray-400/500/600`).

- [ ] **Step 2: Apply the mapping table + Home specifics**

Replace each class per the mapping table. Home specifics:
- Page wrapper: add `bg-surface-0 min-h-screen` if not inherited.
- The recommended start card ("Analyze my network"): `border-2 border-accent` with a `bg-accent-tint text-accent` "Recommended" chip; hover `hover:bg-accent-tint/40` → use `hover:border-line-strong` (avoid opacity; keep it simple with `hover:bg-surface-2`).
- Other start cards: `bg-surface-1 border-line hover:bg-surface-2`.
- Trust chips: `bg-surface-2 text-fg-muted`.
- Recent-audit rows: `hover:bg-surface-2`, grade chip `bg-accent-tint text-accent`.
- Headings `text-fg`, body `text-fg-muted`, meta `text-fg-subtle`.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm run build`
Expected: pass. Then visually check `/` in dark and light: no gray-on-gray, cards read clearly, recommended card stands out.

- [ ] **Step 4: Commit**

```bash
git add src/routes/+page.svelte
git commit -m "feat(ui): restyle Home screen with theme tokens"
```

---

### Task 3: Report screen (`/report`)

**Files:** Modify `src/routes/report/+page.svelte`
**Interfaces:** Consumes Task 1 utilities. Match `src/routes/design-preview/+page.svelte` for the header/score/risk-bar/finding-card look.

- [ ] **Step 1: List classes to replace**

Run: `grep -noE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes/report/+page.svelte`

- [ ] **Step 2: Apply mapping + Report specifics (per the mockup)**

- Header: score number `text-fg`, grade pill colored by band (A/B → `bg-sev-ok-tint text-sev-ok`, C → `bg-sev-warn-tint text-sev-warn`, D/F → `bg-sev-high-tint text-sev-high`).
- Risk bar: a `bg-surface-2` track with segments `bg-sev-high` / `bg-sev-warn` / `bg-sev-ok`.
- Filter chips: active `border-accent bg-accent-tint text-accent`, inactive `border-line text-fg-muted`.
- Finding cards: `bg-surface-1 border-line rounded-xl`; severity icon tile `bg-sev-{high,warn,ok,info}-tint` with the icon in `text-sev-{...}`; title `text-fg`, meta `text-fg-subtle`, body `text-fg-muted`, recommendation link `text-accent`. Map each finding's `status` (gap/recommendation/ok/unknown) to the severity role.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm run build`. Then view `/report` (run an audit first, or it falls back to the most recent) in both themes; confirm severity colors read correctly and the score/risk bar match the mockup.

- [ ] **Step 4: Commit**

```bash
git add src/routes/report/+page.svelte
git commit -m "feat(ui): restyle Report screen to the dark blend design"
```

---

### Task 4: Connect stepper (`/audit`) + onboarding components

**Files:** Modify `src/routes/audit/+page.svelte`, `src/lib/onboarding/ModeStep.svelte`, `src/lib/onboarding/KeyInstructions.svelte`, `src/lib/onboarding/ValidateStep.svelte`, `src/lib/onboarding/SavedKeys.svelte`
**Interfaces:** Consumes Task 1 utilities.

- [ ] **Step 1: List classes to replace across all five files**

Run: `grep -rnoE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes/audit/+page.svelte src/lib/onboarding/`

- [ ] **Step 2: Apply mapping + stepper specifics**

- Inputs (`ModeStep` host field, `ValidateStep` API-key field): `bg-surface-1 border-line focus:border-accent`, text `text-fg`, placeholder `text-fg-subtle`. Keep the API-key field `type="password"`.
- Tier toggle (`KeyInstructions`): segmented buttons; active `bg-accent text-on-accent`, inactive `bg-surface-2 text-fg-muted`.
- Mode buttons (`ModeStep`): selected `bg-accent text-on-accent`, unselected `border-line text-fg`.
- Validate result card (`ValidateStep`): success `bg-sev-ok-tint text-sev-ok`, error `bg-sev-high-tint text-sev-high`.
- Saved-key rows (`SavedKeys`): `bg-surface-1 border-line`, "Use" `text-accent`, "Forget" `text-sev-high`.
- Primary buttons (Validate / Run Audit / Next): `bg-accent text-on-accent hover:bg-accent-hover`. Secondary (Back): `border-line text-fg hover:bg-surface-2`.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm run build`. Then walk `/audit` (Get started → mode → get-key → validate) in both themes; confirm inputs, tier toggle, and the validate card all read clearly.

- [ ] **Step 4: Commit**

```bash
git add src/routes/audit/+page.svelte src/lib/onboarding/
git commit -m "feat(ui): restyle connect stepper + onboarding components"
```

---

### Task 5: Wizard (`/wizard`)

**Files:** Modify `src/routes/wizard/+page.svelte`

- [ ] **Step 1: List classes**

Run: `grep -noE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes/wizard/+page.svelte`

- [ ] **Step 2: Apply mapping + wizard specifics**

- Section headings `text-fg`, prompts `text-fg-muted`.
- Answer choice buttons: `border-line hover:bg-surface-2 text-fg`; selected/primary action `bg-accent text-on-accent`.
- Score/posture display (if present): reuse the Report grade-pill treatment (`bg-sev-*-tint text-sev-*` by band).
- Progress indicator: track `bg-surface-2`, fill `bg-accent`.
- Top issues list: severity dots/text via `text-sev-{high,warn}`.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm run build`. Walk the wizard in both themes.

- [ ] **Step 4: Commit**

```bash
git add src/routes/wizard/+page.svelte
git commit -m "feat(ui): restyle wizard with theme tokens"
```

---

### Task 6: History (`/history`)

**Files:** Modify `src/routes/history/+page.svelte`

- [ ] **Step 1: List classes**

Run: `grep -noE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes/history/+page.svelte`

- [ ] **Step 2: Apply mapping + history specifics**

- Run rows: `bg-surface-1 border-line hover:bg-surface-2`; grade chips `bg-sev-*-tint text-sev-*` by band.
- Any trend/score bars: track `bg-surface-2`, fill `bg-accent`.
- Headings `text-fg`, meta `text-fg-subtle`.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm run build`. View `/history` in both themes.

- [ ] **Step 4: Commit**

```bash
git add src/routes/history/+page.svelte
git commit -m "feat(ui): restyle history with theme tokens"
```

---

### Task 7: Backup (`/backup`) + Update banner

**Files:** Modify `src/routes/backup/+page.svelte`, `src/lib/components/UpdateBanner.svelte`

- [ ] **Step 1: List classes**

Run: `grep -rnoE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes/backup/+page.svelte src/lib/components/UpdateBanner.svelte`

- [ ] **Step 2: Apply mapping**

- Backup: file-picker / drop area `bg-surface-1 border-line`, primary action `bg-accent text-on-accent`, errors `bg-sev-high-tint text-sev-high`, headings/body per mapping.
- UpdateBanner: available banner `bg-accent-tint text-accent` with `bg-accent text-on-accent` "Update now"; up-to-date `bg-sev-ok-tint text-sev-ok`; error `bg-sev-high-tint text-sev-high`; checking `bg-surface-2 text-fg-muted`.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm run build`. View `/backup` in both themes; trigger the "Check for updates" footer button and confirm the up-to-date banner reads in both themes.

- [ ] **Step 4: Commit**

```bash
git add src/routes/backup/+page.svelte src/lib/components/UpdateBanner.svelte
git commit -m "feat(ui): restyle backup screen + update banner"
```

---

### Task 8: Remove the mockup route and final verification

**Files:** Delete `src/routes/design-preview/`

- [ ] **Step 1: Delete the throwaway mockup route**

```bash
git rm -r src/routes/design-preview
```

- [ ] **Step 2: Full-suite + gates**

Run: `npm test` (Expected: PASS, unchanged count) then `npm run typecheck && npm run build` (Expected: both pass).

- [ ] **Step 3: Whole-app visual sweep**

`npm run dev`, then walk every route (`/`, `/audit`, `/backup`, `/wizard`, `/report`, `/history`) in BOTH dark and light. For each, confirm: no hardcoded gray/blue class survived (spot-check with `grep -rnoE "(bg|text|border|hover:bg)-(gray|blue|red|green|amber)-[0-9]+" src/routes src/lib` returning nothing meaningful), text is readable on both backgrounds, and severity colors are correct.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore(ui): remove design-preview mockup route; visual overhaul complete"
```

---

## Self-Review

**1. Spec coverage:** tokens + @theme (Task 1) ✓; Inter bundled (Task 1) ✓; theme store + toggle + no-flash (Task 1) ✓; component patterns applied via the mapping table + per-screen specifics (Tasks 2-7) ✓; all seven screens + onboarding components + update banner covered (Tasks 2-7) ✓; light/dark works everywhere (verified per task + Task 8 sweep) ✓; delete design-preview (Task 8) ✓; no logic changes (Global Constraints, enforced per task) ✓.

**2. Placeholder scan:** Task 1 carries complete code for app.css / theme.ts / app.html / package install. Screen tasks are not placeholders: they carry the authoritative mapping table, a grep to enumerate exactly what to change, per-screen structural specifics, and the reference mockup path. No "TBD"/"handle later".

**3. Type/name consistency:** token utility names (`bg-surface-1`, `text-fg`, `text-fg-muted`, `text-fg-subtle`, `border-line`, `border-line-strong`, `bg-accent`, `hover:bg-accent-hover`, `text-accent`, `bg-accent-tint`, `text-on-accent`, `border-accent`, `bg-sev-{high,warn,ok,info}-tint`, `text-sev-{high,warn,ok,info}`) are defined in Task 1's `@theme` and used identically in every screen task. `theme` store + `toggleTheme`/`setTheme` names match between `theme.ts` and the layout.
