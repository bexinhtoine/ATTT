"""CLI entry point for the isolated investigation evaluation."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.ai_eval.runner import main

if __name__ == "__main__":
    raise SystemExit(main())
