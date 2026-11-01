"""Thin wrapper: python benchmark/evaluate.py [corpus.json] [out_dir]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentic_bom.benchmark import run_corpus  # noqa: E402

if __name__ == "__main__":
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("corpus.json")
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).with_name("reports")
    res = run_corpus(corpus, out)
    print(res["markdown"])
    raise SystemExit(0 if res["all_cases_ran"] else 1)
