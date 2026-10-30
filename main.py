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
    """This process's RSS in MB (Python only, not Firefox children)."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return -1


def _total_rss_mb() -> int:
    """RSS summed across ALL processes in this container.

    Firefox is multi-process, so /proc/self alone hides most of the real
    footprint. Inside a container PID namespace this is the true total.
    """
    total = 0
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            total += int(line.split()[1])
                            break
            except Exception:
                continue
    except Exception:
        return -1
    return total // 1024


def _total_pss_mb() -> int:
    """PSS across all processes — the honest number (shared pages counted once).

    RSS double-counts shared libraries between Firefox processes, which makes
    it read far worse than the cgroup actually sees. PSS is what matters.
    """
    total = 0
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/smaps_rollup") as f:
                    for line in f:
                        if line.startswith("Pss:"):
                            total += int(line.split()[1])
                            break
            except Exception:
                continue
    except Exception:
        return -1
    return total // 1024


def _mem() -> str:
    return f"pss={_total_pss_mb()}MB rss_all={_total_rss_mb()}MB py={_rss_mb()}MB"


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
                # ── Memory tuning for a 512MB / 0.1 vCPU container ──────────
                # Two separate problems addressed here:
                #   (a) Firefox detects 8 host CPUs and spawns one content
                #       process per core — pure waste on 0.1 vCPU, and the
                #       single biggest avoidable RAM cost.
                #   (b) Render blocks unprivileged user namespaces, so the
                #       content sandbox cannot init (/proc/self/uid_map:
                #       EPERM) and renderer children SIGSEGV.
                # NOTE: --no-sandbox / --disable-dev-shm-usage are Chromium
                # flags that Firefox ignores; real control is via prefs.
                firefox_user_prefs={
                    # -- sandbox off (required on Render) --
                    "security.sandbox.content.level": 0,
                    "security.sandbox.gpu.level": 0,
                    "security.sandbox.socket.process.level": 0,
                    # -- collapse to ONE content process --
                    "dom.ipc.processCount": 1,
                    "dom.ipc.processCount.webIsolated": 1,
                    "dom.ipc.processCount.file": 1,
                    "dom.ipc.processCount.extension": 1,
                    "dom.ipc.processCount.privilegedabout": 1,
                    "fission.autostart": False,
                    "fission.webContentIsolationStrategy": 0,
                    # -- kill e10s / extra content processes outright.
                    #    Observed: creating ONE about:blank page cost +189MB,
                    #    meaning additional renderer processes spawn per page.
                    #    These disable the multi-process model entirely.
                    "browser.tabs.remote.autostart": False,
                    "browser.tabs.remote.autostart.2": False,
                    "browser.tabs.remote.disabled-for-a11y": True,
                    "extensions.e10sBlocksEnabling": False,
                    "extensions.e10s.rollout.skipTier1": True,
                    "dom.ipc.multiOptOut": True,
                    # -- software rendering only, no GPU paths --
                    "gfx.webrender.software": True,
                    "gfx.webrender.all": False,
                    "layers.acceleration.disabled": True,
                    "gfx.canvas.accelerated": False,
                    "webgl.disabled": True,
                    # -- shrink caches (we solve, we don't browse) --
                    "browser.cache.memory.capacity": 4096,
                    "browser.cache.disk.enable": False,
                    "browser.cache.offline.enable": False,
                    "browser.cache.memory.enable": True,
                    "media.memory_cache_max_size": 4096,
                    "image.mem.max_decoded_image_kb": 16384,
                    "image.mem.surfacecache.max_size_kb": 16384,
                    "image.cache.size": 2048,
                    "browser.sessionhistory.max_total_viewers": 0,
                    "browser.sessionhistory.max_entries": 5,
                    # -- no speculative network work --
                    "network.prefetch-next": False,
                    "network.dns.disablePrefetch": True,
                    "network.predictor.enabled": False,
                    "network.http.max-connections": 6,
                    "network.http.speculative-parallel-limit": 0,
                    # -- QUIC/HTTP3 off: this is almost certainly what Render
                    #    logs as "Detected new open ports UDP:*". We never
                    #    need it for a challenge solve page.
                    "network.http.http3.enable": False,
                    "network.http.http3.enabled": False,
                    # -- WebRTC off: it was opening stray UDP ports on
                    #    Render ("Detected new open ports UDP:43653") --
                    "media.peerconnection.enabled": False,
                    "media.navigator.enabled": False,
                    "media.autoplay.default": 5,
                    "media.autoplay.blocking_policy": 2,
                    # -- pure background noise we never use --
                    "browser.sessionstore.resume_from_crash": False,
                    "browser.sessionstore.max_tabs_undo": 0,
                    "browser.safebrowsing.malware.enabled": False,
                    "browser.safebrowsing.phishing.enabled": False,
                    "toolkit.telemetry.enabled": False,
                    "datareporting.healthreport.uploadEnabled": False,
                    "browser.newtabpage.enabled": False,
                    "browser.newtabpage.activity-stream.feeds.telemetry": False,
                    "dom.serviceWorkers.enabled": False,
                    "javascript.options.mem.gc_allocation_threshold_mb": 64,
                    "javascript.options.mem.high_water_mark": 32,
                },
            )
            self.browser = await self.camoufox_ctx.start()
            logger.info(f"[Boot] step=browser_up t={time.time()-t0:.1f}s {_mem()}")
            # Reuse the browser's default context instead of creating a new one.
            # Measured: creating a fresh context + page cost +170MB on this
            # 512MB box, because Playwright spins up another process tree.
            # The default context already exists, so this is ~free.
            if getattr(self.browser, "contexts", None):
                self.context = self.browser.contexts[0]
                logger.info(f"[Boot] step=context(reused) t={time.time()-t0:.1f}s {_mem()}")
            else:
                self.context = await self.browser.new_context()
                logger.info(f"[Boot] step=context(new) t={time.time()-t0:.1f}s {_mem()}")
            existing = getattr(self.context, "pages", None) or []
            if existing:
                page = existing[0]
                logger.info(f"[Boot] step=page(reused) t={time.time()-t0:.1f}s {_mem()}")
            else:
                page = await self.context.new_page()
                logger.info(f"[Boot] step=page(new) t={time.time()-t0:.1f}s {_mem()}")
            await self.page_pool.put(page)
            # Prove the prefs actually reached the browser. With
            # media.peerconnection.enabled=False, RTCPeerConnection should be
            # absent. This also tells us whether the UDP ports Render logs are
            # WebRTC (prefs ignored) or QUIC (prefs fine).
            try:
                probe = await page.evaluate(
                    "() => ({webrtc: typeof RTCPeerConnection, "
                    "ua: navigator.userAgent.slice(0, 40), "
                    "hwc: navigator.hardwareConcurrency})"
                )
                logger.info(f"[Boot] prefprobe {probe}")
            except Exception as pe:
                logger.warning(f"[Boot] prefprobe failed: {pe}")
            self.boot_error = None
            self.ready.set()
            logger.success(f"[Boot] ready t={time.time()-t0:.1f}s {_mem()}")

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

            max_rounds = int(os.environ.get("SOLVE_ROUNDS", "2"))
            # Hard wall-clock budget. On 0.1 vCPU a starved Playwright call can
            # take far longer than its nominal timeout, which previously left a
            # task stuck in "process" while holding the only page forever.
            deadline = start + float(os.environ.get("SOLVE_DEADLINE", "150"))

            for round_n in range(1, max_rounds + 1):
                if time.time() >= deadline:
                    logger.warning(f"[Turnstile] deadline reached {task_id}")
                    break
                try:
                    await page.unroute_all()
                except Exception:
                    pass

                await page.route(url_slash, lambda r: r.fulfill(body=html, status=200))
                # The fulfilled document references Cloudflare's api.js, which
                # may never fire "load" on a 0.1 vCPU box. Wait only for DOM
                # and tolerate a timeout — the HTML is already in place.
                try:
                    await page.goto(url_slash, wait_until="domcontentloaded", timeout=20000)
                except Exception as nav_err:
                    logger.warning(f"[Turnstile] nav warning {task_id}: {str(nav_err)[:90]}")

                # Wait for the token to appear instead of clicking ~80 times.
                # One wait_for_function is dramatically cheaper than a
                # click/poll loop when the CPU is this starved.
                try:
                    remaining = max(5000, int((deadline - time.time()) * 1000))
                    handle = await page.wait_for_function(
                        "() => { const el = document.querySelector('[name=cf-turnstile-response]');"
                        " return el && el.value && el.value.length > 20 ? el.value : false; }",
                        timeout=remaining,
                    )
                    token = await handle.json_value()
                    if token:
                        elapsed = round(time.time() - start, 3)
                        self.results[task_id] = {"status": "success", "elapsed_time": elapsed, "value": token}
                        logger.info(f"[Turnstile] OK {task_id} ({elapsed}s) round={round_n}")
                        return
                except Exception as wf_err:
                    logger.warning(f"[Turnstile] wait failed {task_id} round={round_n}: {str(wf_err)[:90]}")

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
