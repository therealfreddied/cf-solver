# cf-solver

> Authenticated single-threaded Cloudflare Turnstile & Clearance solver.  
> Deployed on Render's free tier (Docker), kept alive 24/7 via FleetPinger.

## Usage

All endpoints require a Bearer token:

```
Authorization: Bearer <API_KEY>
```

### Solve Turnstile

```
GET /turnstile?url=https://example.com&sitekey=0x4AAAA...
```

### Solve CF Clearance

```
GET /clearance?url=https://example.com&timeout=30
```

### Poll Result

```
GET /result?id=<task_id>
```

Returns `{"status": "process"}` while running, then `{"status": "success", "value": "..."}` or `{"status": "error"}`.

## Deploy to Render

1. Create a new **Private Service** (Docker) on Render.
2. Set environment variable `API_KEY` to a strong random string.
3. `PORT` is automatically injected by Render.
4. FleetPinger hits `/` (health) every 14 minutes to keep the container awake 24/7.
