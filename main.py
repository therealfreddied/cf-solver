import json
import os
import sys
import time
import uuid
import asyncio
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

security = HTTPBearer()

def verify_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not secrets.compare_digest(credentials.credentials, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials


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

        # Single-threaded: exactly 1 browser context, 1 page
        self.app.add_api_route("/",          self.health,             methods=["GET"])
        self.app.add_api_route("/turnstile",  self.process_turnstile,  methods=["GET"])
        self.app.add_api_route("/clearance",  self.process_clearance,  methods=["GET"])
        self.app.add_api_route("/result",     self.get_result,         methods=["GET"])

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def _startup(self):
        logger.info("Starting headless Camoufox browser (single-thread mode)…")
        self.camoufox_ctx = AsyncCamoufox(
            headless=True,
            exclude_addons=[DefaultAddons.UBO],
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                # Memory reduction flags
                "--memory-pressure-off",
                "--max_old_space_size=300",
            ],
        )
        self.browser = await self.camoufox_ctx.start()
        self.context = await self.browser.new_context()
        page = await self.context.new_page()
        await self.page_pool.put(page)
        asyncio.create_task(self._cleanup_results())
        logger.success("Browser ready — 1 page in pool")

    async def _shutdown(self):
        try:
            await self.browser.close()
        except Exception:
            pass
        logger.info("Browser closed")

    # ── Health ───────────────────────────────────────────────────────────────

    async def health(self):
        return JSONResponse({"status": "ok", "pages_ready": self.page_pool.qsize()})

    # ── Turnstile ────────────────────────────────────────────────────────────

    async def _solve_turnstile(self, task_id, url, sitekey, action=None, cdata=None):
        start = time.time()
        page = await self.page_pool.get()
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
        page = await self.page_pool.get()
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
