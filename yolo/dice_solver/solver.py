# -*- coding: utf-8 -*-
"""Dice top-face sum solver.

This module does not perform detection itself.  It consumes top-face detections
from a future YOLO/ONNX detector and applies the challenge rule:

    answer = candidate whose upward-face sum equals target_number
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .schema import CandidateTopFaces


def solve_from_candidate_faces(target_number: int, candidates: List[CandidateTopFaces]) -> Dict[str, Any]:
    """Return answer index from already-detected candidate top faces."""
    sums = {c.index: c.total for c in candidates}
    matches = [idx for idx, total in sums.items() if total == target_number]
    if len(matches) == 1:
        answer_index: Optional[int] = matches[0]
        status = "unique_match"
    elif len(matches) > 1:
        answer_index = matches[0]
        status = "multiple_matches"
    else:
        # Fallback: nearest sum, useful for debug but should be treated as low confidence.
        answer_index = min(sums, key=lambda idx: abs(sums[idx] - target_number)) if sums else None
        status = "nearest_fallback"

    return {
        "target_number": target_number,
        "candidate_sums": sums,
        "matches": matches,
        "answer_index": answer_index,
        "status": status,
    }


def solve_annotation(annotation: Dict[str, Any]) -> Dict[str, Any]:
    target = int(annotation["target_number"])
    candidates = [CandidateTopFaces.from_dict(x) for x in annotation.get("candidates", [])]
    result = solve_from_candidate_faces(target, candidates)
    result["image"] = annotation.get("image", "")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve dice captcha from top-face annotation/detection JSON")
    parser.add_argument("--annotation", required=True, help="JSON containing target_number and candidate top_faces")
    args = parser.parse_args()

    data = json.loads(Path(args.annotation).read_text(encoding="utf-8-sig"))
    print(json.dumps(solve_annotation(data), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
