#!/bin/bash
set -e

echo "[entry] whoami=$(id -u) HOME=$HOME"
echo "[entry] camoufox cache candidates:"
for p in "$HOME/.cache/camoufox" /root/.cache/camoufox /home/render/.cache/camoufox; do
  if [ -d "$p" ]; then
    echo "[entry]   FOUND $p"
    ls -1 "$p/browsers/official" 2>/dev/null | sed "s/^/[entry]     /" || true
  else
    echo "[entry]   missing $p"
  fi
done

# Camoufox's fingerprint generator queries screen geometry. With no X server
# those providers block indefinitely, so start a virtual framebuffer first and
# hand Firefox a real DISPLAY. Xvfb is installed in the image.
if ! pgrep -x Xvfb >/dev/null 2>&1; then
  echo "[entry] starting Xvfb on :99"
  Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
  for _ in $(seq 1 20); do
    if [ -e /tmp/.X11-unix/X99 ]; then break; fi
    sleep 0.25
  done
fi
export DISPLAY=:99
echo "[entry] DISPLAY=$DISPLAY xvfb=$(pgrep -x Xvfb >/dev/null && echo up || echo down)"

exec python3 main.py
