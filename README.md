# ViharaOS Desktop (Public Distribution)

This repository hosts the **public desktop distribution** for ViharaOS.

The main ViharaOS monorepo (source code for the API, web app, and desktop
shell) remains **private**. This repo contains only what is needed to build
and ship the desktop installer:

- `src-tauri/` — Tauri Rust backend + config
- `out/` — Static export of the ViharaOS web frontend (embedded in the app)
- `.github/workflows/desktop-release.yml` — Build + release workflow

## Why a separate public repo?

- **Public GitHub Releases** — installers can be downloaded without GitHub login
- **Tauri auto-update** — `latest.json` is served from public GitHub Releases
- **No backend proxy** — no Worker, no R2, no API token required for downloads
- **Public GitHub Actions minutes** — builds run on public runners

## Release flow

1. In the private ViharaOS repo:
   ```bash
   pnpm --filter @viharaos/web build:static
   node scripts/export-desktop-public.mjs
   ```
2. Sync `dist-public-desktop/` into this repo:
   ```bash
   rsync -av --delete dist-public-desktop/ ../viharaos-desktop/
   # or: robocopy dist-public-desktop ..\viharaos-desktop /MIR
   ```
3. Commit and push:
   ```bash
   cd ../viharaos-desktop
   git add .
   git commit -m "release: prepare desktop v0.1.x"
   git push origin main
   ```
4. Run the **desktop-release** workflow (Actions tab → Run workflow → enter version)
5. Verify the release has `latest.json`, signatures, and installers
6. Install an older app build and confirm the update banner appears

## Tauri updater

The updater endpoint is:
```
https://github.com/aakash-priyadarshi/viharaos-desktop/releases/latest/download/latest.json
```

This is configured in `src-tauri/tauri.conf.json` under `plugins.updater.endpoints`.

## Signing (optional but recommended)

For signed updates, set these repository secrets:
- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`

Without signing, the updater will still download but won't verify signatures.
