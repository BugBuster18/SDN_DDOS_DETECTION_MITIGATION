# Sourced by the demo scripts. Resolves the project root and common paths.
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(cd "$DEMO_DIR/../.." && pwd)"
LOG_DIR="$PROJECT/experiments/results/demo/logs"
REST="http://127.0.0.1:8080/ddos"
need_root() { if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo:  sudo $0"; exit 1; fi; }
run_py() { python3 "$DEMO_DIR/demo_runner.py" "$@"; }
