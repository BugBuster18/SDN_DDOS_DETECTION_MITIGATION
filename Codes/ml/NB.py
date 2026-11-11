"""Compatibility entry point: all models now use the shared preprocessing and evaluation pipeline."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ddos_ml.training import main

if __name__ == "__main__":
    main()
