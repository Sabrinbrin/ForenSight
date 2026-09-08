#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backend_root="$project_root/backend"
backend_python="$backend_root/.venv/bin/python"
url="http://127.0.0.1:5173/ForenSight/"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v npm >/dev/null || { echo "npm is required" >&2; exit 1; }

if [[ ! -x "$backend_python" ]]; then
  python3 -m venv "$backend_root/.venv"
  "$backend_python" -m pip install -r "$backend_root/requirements-linux.txt"
fi
if [[ ! -d "$project_root/node_modules" ]]; then
  npm --prefix "$project_root" install
fi

if ! curl --silent --fail http://127.0.0.1:8000/health >/dev/null 2>&1; then
  (cd "$backend_root" && nohup "$backend_python" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 >"$project_root/.forensight-backend.log" 2>&1 &)
fi
if ! curl --silent --fail "$url" >/dev/null 2>&1; then
  (cd "$project_root" && nohup npm run dev -- --host 127.0.0.1 >"$project_root/.forensight-frontend.log" 2>&1 &)
fi

for _ in $(seq 1 40); do
  if curl --silent --fail http://127.0.0.1:8000/health >/dev/null 2>&1 && curl --silent --fail "$url" >/dev/null 2>&1; then
    echo "ForenSight is ready at $url"
    exit 0
  fi
  sleep 0.5
done
echo "ForenSight did not start within 20 seconds. Check .forensight-*.log." >&2
exit 1
