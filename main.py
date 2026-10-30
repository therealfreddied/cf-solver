import json
import os
import sys
import time
import uuid
import asyncio
import hashlib
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from loguru import logger
from camoufox import DefaultAddons
from camoufox.async_api import AsyncCamoufox
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ── Config ──────────────────────────────────────────────────────────────────
API_KEY = os.environ.get("API_KEY", "changeme")
PORT    = int(os.environ.get("PORT", 10000))
HOST    = os.environ.get("HOST", "0.0.0.0")

security = HTTPBearer(auto_error=False)


def _expected_key() -> str:
    # Read on every request so an env change never needs a code change.
    return os.environ.get("API_KEY", "changeme")


def _sha8(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def _rss_mb() -> int:
    """Current process RSS in MB — cheap OOM visibility on a 512MB box."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return -1


def verify_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    expected = _expected_key()
    got = credentials.credentials if credentials else ""
    if not secrets.compare_digest(got.encode(), expected.encode()):
        logger.warning(
            f"[auth] reject got_sha8={_sha8(got)} got_len={len(got)} "
            f"expected_sha8={_sha8(expected)} expected_len={len(expected)}"
        )
        raise HTTPException(status_code=401, detail="Invalid API key")
    return got


# ── Solver ───────────────────────────────────────────────────────────────────
class TurnstileSolver:

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Solver</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
</head>
<body><!-- cf turnstile --></body>
</html>"""

    def __init__(self):
        @asynccontextmanager
        async def lifespan(app):
            await self._startup()
            yield
            await self._shutdown()

        self.app = FastAPI(lifespan=lifespan)
        self.page_pool: asyncio.Queue = asyncio.Queue()
        self.camoufox_ctx = None
        self.browser = None
        self.results: dict = {}
        self.context = None

        # Lazy, non-blocking browser boot.
        # uvicorn MUST bind the port immediately or Render's port scanner
        # times out and kills the container before it ever goes live.
        self.ready = asyncio.Event()
        self._boot_lock = asyncio.Lock()
        self.boot_error: str | None = None

        # Single-threaded: exactly 1 browser context, 1 page
        self.app.add_api_route("/",          self.health,             methods=["GET"])
        self.app.add_api_route("/turnstile",  self.process_turnstile,  methods=["GET"])
        self.app.add_api_route("/clearance",  self.process_clearance,  methods=["GET"])
        self.app.add_api_route("/result",     self.get_result,         methods=["GET"])

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def _startup(self):
        # Returns immediately so the HTTP server binds its port right away.
        logger.info("HTTP server starting (browser boots lazily on demand)…")
        _k = _expected_key()
        logger.info(f"[auth] expected key sha8={_sha8(_k)} len={len(_k)}")
        asyncio.create_task(self._cleanup_results())
        if os.environ.get("PREWARM", "").lower() in ("1", "true", "yes"):
            asyncio.create_task(self._ensure_browser())

    async def _ensure_browser(self):
        """Boot Camoufox once, on demand. Safe to call concurrently."""
        if self.ready.is_set():
            return
        async with self._boot_lock:
            if self.ready.is_set():
                return
            t0 = time.time()
            logger.info(f"[Boot] step=begin rss={_rss_mb()}MB cpu={os.cpu_count()}")
            self.camoufox_ctx = AsyncCamoufox(
                headless=True,
                humanize=False,
                exclude_addons=[DefaultAddons.UBO],
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--memory-pressure-off",
                ],
            )
            self.browser = await self.camoufox_ctx.start()
            logger.info(f"[Boot] step=browser_up t={time.time()-t0:.1f}s rss={_rss_mb()}MB")
            self.context = await self.browser.new_context()
            logger.info(f"[Boot] step=context t={time.time()-t0:.1f}s")
            page = await self.context.new_page()
            logger.info(f"[Boot] step=page t={time.time()-t0:.1f}s")
            await self.page_pool.put(page)
            self.boot_error = None
            self.ready.set()
            logger.success(f"[Boot] ready t={time.time()-t0:.1f}s rss={_rss_mb()}MB")

    async def _acquire_page(self, timeout=None):
        """Boot the browser if needed, then lease the single page."""
        if timeout is None:
            timeout = int(os.environ.get("BOOT_TIMEOUT", "600"))
        try:
            await asyncio.wait_for(self._ensure_browser(), timeout=timeout)
        except asyncio.TimeoutError:
            self.boot_error = "browser boot timeout"
            raise
        except Exception as e:
            self.boot_error = f"{type(e).__name__}: {e}"
            logger.error(f"[Boot] {self.boot_error}")
            raise
        return await asyncio.wait_for(self.page_pool.get(), timeout=120)

    async def _shutdown(self):
        try:
            await self.browser.close()
        except Exception:
            pass
        logger.info("Browser closed")

    # ── Health ───────────────────────────────────────────────────────────────

    async def health(self):
        # Always 200 and instant — this is what FleetPinger hits to keep the
        # free instance from sleeping. Browser state is reported, not required.
        return JSONResponse({
            "status": "ok",
            "browser_ready": self.ready.is_set(),
            "pages_ready": self.page_pool.qsize(),
            "boot_error": self.boot_error,
        })

    # ── Turnstile ────────────────────────────────────────────────────────────

    async def _solve_turnstile(self, task_id, url, sitekey, action=None, cdata=None):
        start = time.time()
        try:
            page = await self._acquire_page()
        except Exception as e:
            elapsed = round(time.time() - start, 3)
            self.results[task_id] = {"status": "error", "elapsed_time": elapsed, "value": f"browser_unavailable: {e}"}
            logger.error(f"[Turnstile] no browser {task_id}: {e}")
            return
        try:
            url_slash = url if url.endswith("/") else url + "/"
            div = (
                f'<div class="cf-turnstile" style="background:white;width:70px;"'
                f' data-sitekey="{sitekey}"'
                + (f' data-action="{action}"' if action else "")
                + (f' data-cdata="{cdata}"'   if cdata  else "")
                + "></div>"
            )
            html = self.HTML_TEMPLATE.replace("<!-- cf turnstile -->", div)

            for round_n in range(1, 3):
                try:
                    await page.unroute_all()
                except Exception:
                    pass

                await page.route(url_slash, lambda r: r.fulfill(body=html, status=200))
                await page.goto(url_slash)
                await asyncio.sleep(3)

                solved = False
                for _ in range(80):
                    try:
                        try:
                            await page.click(".cf-turnstile", timeout=500)
                        except Exception:
                            pass
                        val = await page.input_value("[name=cf-turnstile-response]", timeout=400)
                        if val:
                            elapsed = round(time.time() - start, 3)
                            self.results[task_id] = {"status": "success", "elapsed_time": elapsed, "value": val}
                            logger.info(f"[Turnstile] OK {task_id} ({elapsed}s) round={round_n}")
                            solved = True
                            return
                    except Exception:
                        pass
                    await asyncio.sleep(0.3)

                logger.warning(f"[Turnstile] Round {round_n} failed — {task_id}")

            elapsed = round(time.time() - start, 3)
            self.results[task_id] = {"status": "error", "elapsed_time": elapsed, "value": "captcha_fail"}

        except Exception as e:
            elapsed = round(time.time() - start, 3)
            self.results[task_id] = {"status": "error", "elapsed_time": elapsed, "value": str(e)}
            logger.error(f"[Turnstile] Exception {task_id}: {e}")
        finally:
            try:
                await page.unroute_all()
            except Exception:
                pass
            await self.page_pool.put(page)

    async def process_turnstile(
        self,
        url: str = Query(...),
        sitekey: str = Query(...),
        action: str = Query(None),
        cdata: str = Query(None),
        _: str = Depends(verify_key),
    ):
        task_id = str(uuid.uuid4())
        self.results[task_id] = {"status": "process", "start_time": time.time()}
        asyncio.create_task(self._solve_turnstile(task_id, url, sitekey, action, cdata))
        return JSONResponse({"task_id": task_id, "status": "accepted"}, status_code=202)

    # ── Clearance ────────────────────────────────────────────────────────────

    async def _solve_clearance(self, task_id, url, timeout=30):
        start = time.time()
        try:
            page = await self._acquire_page()
        except Exception as e:
            elapsed = round(time.time() - start, 3)
            self.results[task_id] = {"status": "error", "elapsed_time": elapsed, "value": f"browser_unavailable: {e}"}
            logger.error(f"[Clearance] no browser {task_id}: {e}")
            return
        try:
            ua = await page.evaluate("navigator.userAgent")
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)

            cf_clearance = None
            deadline = time.time() + timeout
            while time.time() < deadline:
                title = await page.title()
                cookies = await self.context.cookies()
                cf = next((c for c in cookies if c["name"] == "cf_clearance"), None)
                if cf and "just a moment" not in title.lower():
                    cf_clearance = cf["value"]
                    break
                await asyncio.sleep(1)

            elapsed = round(time.time() - start, 3)
            if cf_clearance:
                all_cookies = await self.context.cookies()
                cookie_hdr = "; ".join(f"{c['name']}={c['value']}" for c in all_cookies)
                self.results[task_id] = {
                    "status": "success", "elapsed_time": elapsed,
                    "cf_clearance": cf_clearance, "user_agent": ua, "cookies": cookie_hdr,
                }
                logger.success(f"[Clearance] OK {task_id} ({elapsed}s)")
            else:
                self.results[task_id] = {"status": "error", "elapsed_time": elapsed, "value": "clearance_fail"}
                logger.warning(f"[Clearance] Failed {task_id}")

        except Exception as e:
            elapsed = round(time.time() - start, 3)
            self.results[task_id] = {"status": "error", "elapsed_time": elapsed, "value": str(e)}
            logger.error(f"[Clearance] Exception {task_id}: {e}")
        finally:
            try:
                await self.context.clear_cookies()
            except Exception:
                pass
            try:
                await page.goto("about:blank")
            except Exception:
                pass
            await self.page_pool.put(page)

    async def process_clearance(
        self,
        url: str = Query(...),
        timeout: int = Query(30),
        _: str = Depends(verify_key),
    ):
        task_id = str(uuid.uuid4())
        self.results[task_id] = {"status": "process", "start_time": time.time()}
        asyncio.create_task(self._solve_clearance(task_id, url, timeout))
        return JSONResponse({"task_id": task_id, "status": "accepted"}, status_code=202)

    # ── Result ───────────────────────────────────────────────────────────────

    async def get_result(
        self,
        task_id: str = Query(..., alias="id"),
        _: str = Depends(verify_key),
    ):
        if task_id not in self.results:
            return JSONResponse({"status": "error", "message": "task_id invalid or expired"}, status_code=404)
        result = self.results[task_id]
        if result.get("status") == "process":
            return JSONResponse({"status": "process"})
        self.results.pop(task_id, None)
        return JSONResponse(result)

    # ── Background cleanup ────────────────────────────────────────────────────

    async def _cleanup_results(self):
        while True:
            await asyncio.sleep(300)
            now = time.time()
            expired = [
                tid for tid, r in list(self.results.items())
                if isinstance(r, dict) and now - r.get("start_time", now) > 300
            ]
            for tid in expired:
                self.results.pop(tid, None)
            if expired:
                logger.info(f"[Cleanup] Removed {len(expired)} expired results")


# ── Entrypoint ────────────────────────────────────────────────────────────────

solver = TurnstileSolver()
app = solver.app

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
