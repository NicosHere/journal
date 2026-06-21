# Quiet Journal

A beautiful, minimal Cloudflare Worker journal. The first sign-in for a username creates that private journal; future sign-ins require the same password. Entries are saved with exact ISO timestamps, displayed in the visitor's local time, and automatically grouped by month.

The app uses a Durable Object per username for password metadata, sessions, and entries. That keeps the project agent-friendly: there are no pre-created KV namespace IDs to copy into `wrangler.toml` before deployment.

## Run locally

```bash
npm install
npm test
npm run dev
```

## Temporary deploy for agents

Cloudflare's temporary accounts flow lets agents deploy without a pre-existing Cloudflare login by running Wrangler with `--temporary`. The deployment remains live for 60 minutes and can be claimed from the URL Wrangler prints.

```bash
npm run deploy:temp
```

## Permanent deploy

After authenticating Wrangler with your own Cloudflare account, run:

```bash
npm run deploy
```
