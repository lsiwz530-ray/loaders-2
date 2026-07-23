# North Admin Panel — Draw SCRIPT (Railway)

Private, second-panel control center for the Draw SCRIPT ecosystem. Purple /
black / white dark-glassmorphism design.

## What it controls

- **EXE files** — upload / replace / version the loader (`DrawLoader.exe`).
  Keys dashboard automatically serves the current version.
- **Site images** — logo / hero / background used by the keys dashboard.
- **Admins** — add / remove users with `dev` role (same permissions as `North`).
- **Analytics** — who downloaded what, when, from which IP, how many times,
  charts by day, top users, top files.

## Deploy on Railway (same project as keys-dashboard)

1. Create a second service in the SAME Railway project.
2. Point it to the same **Postgres** plugin (the `DATABASE_URL` reference is
   shared automatically) and mount the **same Volume** at `/data`.
3. Set env vars:
   - `SESSION_SECRET` — same as keys dashboard (or independent, both work)
   - `ADMIN_USERNAME=North`, `ADMIN_PASSWORD=North123`
4. Deploy.

## Login

- Username: `North`
- Password: `North123`

Only users with role `dev` can enter this panel.

## URL

Assign the admin service its own domain in Railway (e.g.
`admin.your-domain.com`). Keep it private — do not link to it from the public
keys site.
