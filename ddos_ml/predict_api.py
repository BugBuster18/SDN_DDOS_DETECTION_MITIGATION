"""Local HTTP prediction service for the Ryu DDoS detection controller."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ddos_ml.runtime import load_model, live_feature_frame

HOST = os.environ.get("DDOS_ML_API_HOST", "127.0.0.1")
PORT = int(os.environ.get("DDOS_ML_API_PORT", "8765"))
MAX_BODY_BYTES = 2_000_000
MAX_FLOWS = 2000

MODEL, METADATA = load_model()


class PredictionHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send_json(404, {"error": "Not found"})
            return

        self._send_json(200, {
            "status": "ok",
            "selected_model": METADATA.get("selected_model"),
            "model_file": METADATA.get("model_file"),
        })

    def do_POST(self) -> None:
        if self.path != "/predict":
            self._send_json(404, {"error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_BODY_BYTES:
                self._send_json(413, {"error": "Invalid request size"})
                return

            payload = json.loads(self.rfile.read(content_length))
            flows = payload.get("flows") if isinstance(payload, dict) else None

            if not isinstance(flows, list) or not flows:
                self._send_json(400, {"error": "'flows' must be a non-empty list"})
                return

            if len(flows) > MAX_FLOWS:
                self._send_json(413, {"error": f"Maximum {MAX_FLOWS} flows per request"})
                return

            if not all(isinstance(flow, dict) for flow in flows):
                self._send_json(400, {"error": "Every flow must be a JSON object"})
                return

            features = live_feature_frame(flows)
            labels = MODEL.predict(features)
            probabilities = MODEL.predict_proba(features)[:, 1]

            predictions = [
                {
                    "prediction": int(label),
                    "attack_probability": float(probability),
                }
                for label, probability in zip(labels, probabilities)
            ]

            self._send_json(200, {"predictions": predictions})

        except Exception as exc:
            print(f"Prediction request failed: {exc}", flush=True)
            self._send_json(500, {"error": "Prediction failed"})

    def log_message(self, fmt: str, *args) -> None:
        print(f"[ML API] {fmt % args}", flush=True)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), PredictionHandler)
    print(
        f"ML prediction API listening on http://{HOST}:{PORT}",
        flush=True,
    )
    print(
        f"Model: {METADATA.get('selected_model')} "
        f"({METADATA.get('model_file')})",
        flush=True,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ML prediction API", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
