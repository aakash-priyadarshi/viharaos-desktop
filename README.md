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

## Microsoft Store distribution

The workflow includes a `store-publish` job that submits the NSIS installer
to the Microsoft Store via the [MSStore Developer CLI](https://learn.microsoft.com/en-us/windows/apps/publish/msstore-dev-cli/overview).
The Store wraps the installer in MSIX and signs it with Microsoft's certificate,
so users who install from the Store see no SmartScreen warning.

### Prerequisites

1. **Partner Center**: Register as a developer at https://partner.microsoft.com/
2. **Create product**: In Partner Center → Apps and Games → New Product →
   select "EXE or MSI app" → reserve the name "ViharaOS"
3. **Entra ID app registration**: Follow
   https://learn.microsoft.com/en-us/windows/apps/publish/partner-center/associate-existing-azure-ad-tenant-with-partner-center-account
   to associate an Entra ID tenant with your Partner Center account, then
   register an app in Entra ID and add it to Partner Center with the Manager role.
4. **Get your IDs**:
   - Tenant ID: https://entra.microsoft.com/ → Overview → Tenant ID
   - Client ID: Entra admin center → App registrations → your app → Application ID
   - Client Secret: App registrations → Certificates & secrets → create new
   - Seller ID: Partner Center → Account settings → Developer settings → Publisher ID
   - Product ID: Partner Center → your app product page → Product identity

### GitHub repository secrets

Add these secrets to the `viharaos-desktop` repo (Settings → Secrets → Actions):

| Secret | Value |
|---|---|
| `AZURE_AD_TENANT_ID` | Your Entra ID tenant ID |
| `AZURE_AD_APPLICATION_CLIENT_ID` | Your Entra ID app registration client ID |
| `AZURE_AD_APPLICATION_SECRET` | Your Entra ID app registration client secret |
| `SELLER_ID` | Your Partner Center Seller/Publisher ID |

The `store-publish` job only runs when these four secrets are present. If they are
not set, the job builds the Store installer and uploads it to the GitHub release
but skips the Store submission.

The `MSSTORE_PRODUCT_ID` is configured as an environment variable in
`.github/workflows/desktop-release.yml` (the `store-publish` job). Update it to
your Store product ID if it differs.

### First-time setup

1. Submit the first app package manually in Partner Center (upload the
   `ViharaOS_x.x.x_x64-setup.exe` from a GitHub release, set the silent
   install parameter to `/S`, and complete the store listing).
2. After the first submission is published, the `store-publish` job can
   automate subsequent updates.
