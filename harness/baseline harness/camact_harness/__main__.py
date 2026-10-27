"""Launch the canonical Baseline CLI."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from baseline_harness.cli import main
raise SystemExit(main())
