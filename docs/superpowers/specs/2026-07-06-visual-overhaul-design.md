# Visual Overhaul Design Spec

**Date:** 2026-07-06
**Status:** Approved (pending spec review)
**Scope:** Pure visual redesign of the desktop app (SvelteKit + Tailwind v4). No changes to audit logic, findings, wizard flow, or data. Every screen keeps its exact behavior; only its look changes.

## Goal

Move the app from default-Tailwind (one blue, gray cards, light-only, system font) to a deliberate, polished identity. Direction chosen during brainstorming: a **dark shell with calm, roomy information design** ("blend"), a **UniFi-blue accent**, **Inter** as the UI font, and a **dark-default theme with a working light toggle**. Reference mockup: the throwaway `src/routes/design-preview/+page.svelte` route on this branch.

## Design tokens

All colors go through CSS custom properties so both themes and future tweaks live in one place. Defined in `src/app.css`, dark values on `:root`, light values under `:root[data-theme="light"]`. Components never hardcode hex; they use token-backed utilities.

### Surfaces and text

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--surface-0` | `#0e1116` | `#f6f7f9` | Page background |
| `--surface-1` | `#161b22` | `#ffffff` | Cards, panels |
| `--surface-2` | `#1c222b` | `#ffffff` | Elevated / hover, icon tiles |
| `--border` | `#232a34` | `#e5e7eb` | Hairline borders |
| `--border-strong` | `#2f3742` | `#d1d5db` | Emphasis / hover borders |
| `--text-primary` | `#e6eaf0` | `#111827` | Headings, key text |
| `--text-secondary` | `#9aa5b4` | `#4b5563` | Supporting text |
| `--text-muted` | `#6b7684` | `#9ca3af` | Meta, hints, placeholders |

### Accent (UniFi blue)

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--accent` | `#3b82f6` | `#1d6fe0` | Primary actions, active tab, links |
| `--accent-hover` | `#2f74e6` | `#1a63c9` | Hover |
| `--accent-tint` | `#16233b` | `#e8f1fe` | Accent-tinted backgrounds (active chips) |
| `--on-accent` | `#ffffff` | `#ffffff` | Text/icons on a filled accent |

### Severity (calm, no glow)

| Role | Dark color | Dark tint | Light color | Light tint |
| --- | --- | --- | --- | --- |
| high / gap | `#f2555a` | `#241417` | `#dc2626` | `#fef2f2` |
| warning / recommendation | `#e0a13a` | `#241d10` | `#b45309` | `#fffbeb` |
| ok / good | `#34d399` | `#10251d` | `#059669` | `#ecfdf5` |
| info / unknown | `#5b9bf6` | `#131f38` | `#2563eb` | `#eff6ff` |

### Typography, radius, spacing

- Font: **Inter**, bundled locally (works offline in the Tauri build). Stack: `'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif`. Weights 400 / 500 / 600.
- Type scale: h1 24/600, h2 18/600, h3 15/600, body 14/400 (line-height 1.55), meta 12/400.
- Radius: `10px` controls, `12px` cards, `999px` pills.
- Spacing: card padding `16px`, section gaps `12–24px`.

## Theme system

- `src/app.css`: `@theme` maps the CSS variables into Tailwind so components use semantic utilities (`bg-surface-1`, `text-secondary`, `border-default`, `bg-accent`, etc.), plus the `:root` / `:root[data-theme="light"]` variable blocks and the Inter `@font-face`.
- `src/lib/stores/theme.ts`: a persisted `theme` store (`'dark' | 'light'`). On load it reads `localStorage`, falling back to `prefers-color-scheme` (defaulting to dark). It sets `data-theme` on `document.documentElement` and writes changes back to `localStorage`.
- Toggle control: a sun/moon button in the layout footer, next to the version and "Check for updates". Instant, no reload.
- No flash: the initial `data-theme` is applied as early as possible (an inline snippet in `app.html` reads `localStorage`/`prefers-color-scheme` before first paint).

## Component patterns

These replace the current ad-hoc styling. Each is defined once (as a Svelte component or a shared class) and reused.

- **Top nav** (`+layout.svelte`): sticky, `--surface-0` background, `--border` bottom, tabs with an accent underline on the active tab. Footer holds version, "Check for updates", and the theme toggle.
- **Card**: `--surface-1`, 1px `--border`, 12px radius, 16px padding.
- **Finding card**: a severity icon tile (severity tint background, severity-color icon) + title + meta line (`section · id · effort`) + body + an accent recommendation link. Roomy, one per row.
- **Score / grade**: large number with a grade pill colored by band (A/B green, C amber, D/F red) and a segmented risk bar (high/warn/ok widths).
- **Filter chips**: pills; active = accent border + `--accent-tint` background + accent text; inactive = `--border` + secondary text.
- **Buttons**: primary (accent fill, `--on-accent`), secondary (border + surface hover), ghost (text only). One primary per view.
- **Inputs**: `--surface-1` background, `--border`, accent focus ring; the API-key field stays masked.
- **Badges / status pills**: severity tints for finding status; neutral for meta.
- **Empty states**: icon + one-line invitation, muted text.

## Per-screen application

Same content and flow, restyled with the tokens and patterns above:

- **Home (`/`)**: dark hero (value prop + trust chips), the three start cards (the recommended card gets a 2px accent border and a "Recommended" chip), recent-audits list with grade chips.
- **Connect stepper (`/audit`)**: the Step 0 saved-keys / mode / get-key / validate flow, restyled. Tier toggle as a segmented control; the validate result as a success/error card using severity tokens.
- **Wizard (`/wizard`)**: profile / skills / question flow with a progress indicator; answer choices as buttons.
- **Report (`/report`)**: per the mockup (header + score + risk bar + filter chips + finding cards). Export button as a secondary button.
- **History (`/history`)**: run list with grade chips and a simple score trend.
- **Backup (`/backup`)**: file-picker screen restyled.
- **Update banner**: retinted to the tokens so it works in both themes.

## Implementation approach

1. Add tokens + Inter + theme system (`app.css`, `theme.ts`, `app.html` no-flash snippet, layout toggle). This is the foundation every screen depends on.
2. Convert screens one at a time, replacing hardcoded `bg-blue-600` / `bg-gray-50` / `text-gray-*` etc. with the semantic token utilities. Order by impact: layout/nav, Home, Report, Connect, Wizard, History, Backup, Update banner.
3. Delete the throwaway `src/routes/design-preview/` route before merge.

Keep changes visual. Do not touch `src/audit/**`, `src/wizard/*.ts` logic, `src/db/**`, or `src-tauri/**` behavior.

## Testing

- The existing Vitest suite covers the audit core and logic, not components, so it is unaffected and must stay green (`npm test`).
- `npm run typecheck` and `npm run build` must pass after each screen.
- Visual verification per screen via the dev server (`npm run dev`) in both dark and light, checking contrast and that no element is hardcoded to one theme (the "would this be readable if the background flipped?" test).

## Out of scope

- No new features, findings, or flow changes.
- No animation system beyond simple hover/focus transitions.
- No custom iconography beyond the existing inline SVGs / a lightweight icon set.
- Mobile/responsive layouts (this is a desktop window; it stays desktop-first).
