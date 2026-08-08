# Repository Guidelines

Never name, reference, or compare against competitor games/products in code, comments, commit messages, or docs in this repo.

**discord-vscode-hexscript** is a fork of [iCrawl/discord-vscode](https://github.com/iCrawl/discord-vscode) that teaches Discord Rich Presence to recognise HexScript. See [README.md](README.md).

## This is a fork — keep the delta small

The entire reason this repo exists is HexScript recognition. Everything else is upstream code that should stay as close to upstream as possible, so that pulling in new releases stays a merge rather than a rewrite.

Before changing a file, ask whether the change is *HexScript-specific*. If it is not, it probably belongs upstream instead. The intended delta is:

- `src/data/languages.json` — the `hexscript` entry
- `assets/` — the HexScript icon
- `package.json` — fork identity (`name`, `publisher: hexbe`)
- `README.md` — what differs from upstream

Anything beyond that is drift, and drift is what makes the next upstream sync painful.

## Build & Development

Uses **pnpm** (not npm — there is a `pnpm-lock.yaml` and a workspace file; mixing package managers will produce a second lockfile and inconsistent installs).

```bash
pnpm install
pnpm run dev      # esbuild watch
pnpm run build    # lint + esbuild bundle
pnpm run lint     # tsc --noEmit + prettier + eslint
pnpm run format   # autofix
```

`pnpm run build` runs the linter first and will fail the build on lint errors — that is deliberate, do not bypass it.

## Adding or changing language recognition

Language mappings live in `src/data/languages.json`, keyed by the VS Code language ID. The ID must match what the HexScript language extension registers (see the `hexscript-language-support` repo) — if they disagree, Rich Presence silently falls back to a generic file icon rather than erroring, so a typo here is invisible until someone opens a `.hexs` file and notices the wrong icon.

Icons are referenced by name and must exist as uploaded Discord application art assets, not just as files in `assets/`. A missing asset also fails silently.

## Packaging

The committed `.vsix` is a build artifact. Regenerate it rather than hand-editing, and bump the version in `package.json` when you do — VS Code will not reinstall over an identical version.

## Before claiming a change is done

- [ ] Ran `pnpm run build` (which includes lint + typecheck), not just `dev`.
- [ ] Any language-ID change matches what `hexscript-language-support` registers.
- [ ] Change is HexScript-specific; unrelated fixes go upstream instead.
- [ ] Used pnpm, and did not add a `package-lock.json`.
