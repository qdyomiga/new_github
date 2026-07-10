# -*- coding: utf-8 -*-
"""YOLO top-face inference for dice FunCaptcha strips.

Pipeline:
  full 2400x400 image -> crop 12 candidate tiles -> YOLO detects top_1..top_6
  -> class-agnostic duplicate suppression -> sum each candidate's upward faces
  -> optional target-number matching.

Target OCR is intentionally not handled here yet. Pass --target manually until the
OCR module is added.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from PIL import Image

from .layout import DiceLayout, crop_candidates, open_rgb
from .schema import CandidateTopFaces, TopFaceDetection
from .solver import solve_from_candidate_faces

CLASS_NAMES = {i: f"top_{i + 1}" for i in range(6)}


def _to_scalar(value: Any) -> Any:
    """Convert torch/numpy/list scalar-ish values to plain Python values."""
    if isinstance(value, (list, tuple)):
        if not value:
            return 0
        return _to_scalar(value[0])
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return value


def _to_float_list(values: Any) -> List[float]:
    """Convert tensor/list-like xyxy values to four floats."""
    if hasattr(values, "tolist"):
        values = values.tolist()
    if isinstance(values, (list, tuple)) and len(values) == 1 and isinstance(values[0], (list, tuple)):
        values = values[0]
    return [float(x) for x in list(values)[:4]]


def _box_to_detection(box: Any, names: Dict[int, str]) -> TopFaceDetection:
    cls_id = int(_to_scalar(getattr(box, "cls", 0)))
    confidence = float(_to_scalar(getattr(box, "conf", 1.0)))
    xyxy = _to_float_list(getattr(box, "xyxy", [0, 0, 0, 0]))

    label = str(names.get(cls_id, CLASS_NAMES.get(cls_id, f"top_{cls_id + 1}")))
    if label.isdigit():
        label = f"top_{int(label) + 1}"
    if not label.startswith("top_"):
        label = CLASS_NAMES.get(cls_id, f"top_{cls_id + 1}")
    value = int(label.rsplit("_", 1)[-1])
    return TopFaceDetection(label=label, value=value, box=xyxy, confidence=confidence)


def _iou(box_a: Sequence[float], box_b: Sequence[float]) -> float:
    ax0, ay0, ax1, ay1 = [float(x) for x in box_a]
    bx0, by0, bx1, by1 = [float(x) for x in box_b]
    inter_x0 = max(ax0, bx0)
    inter_y0 = max(ay0, by0)
    inter_x1 = min(ax1, bx1)
    inter_y1 = min(ay1, by1)
    inter_w = max(0.0, inter_x1 - inter_x0)
    inter_h = max(0.0, inter_y1 - inter_y0)
    inter = inter_w * inter_h
    area_a = max(0.0, ax1 - ax0) * max(0.0, ay1 - ay0)
    area_b = max(0.0, bx1 - bx0) * max(0.0, by1 - by0)
    denom = area_a + area_b - inter
    return inter / denom if denom > 0 else 0.0


def dedupe_faces(faces: Iterable[TopFaceDetection], *, iou_threshold: float = 0.50) -> List[TopFaceDetection]:
    """Class-agnostic NMS: one physical top face may be predicted as multiple classes."""
    kept: List[TopFaceDetection] = []
    for face in sorted(faces, key=lambda x: x.confidence, reverse=True):
        if all(_iou(face.box, existing.box) < iou_threshold for existing in kept):
            kept.append(face)
    return kept


def result_to_candidate_faces(index: int, result: Any, *, iou_threshold: float = 0.50) -> CandidateTopFaces:
    """Convert one Ultralytics result object into CandidateTopFaces."""
    raw_names = getattr(result, "names", None) or CLASS_NAMES
    names = {int(k): str(v) for k, v in dict(raw_names).items()}
    boxes = getattr(result, "boxes", []) or []
    faces = [_box_to_detection(box, names) for box in boxes]
    faces = dedupe_faces(faces, iou_threshold=iou_threshold)
    return CandidateTopFaces(index=index, top_faces=faces)


def predict_candidates_with_model(
    model: Any,
    candidate_images: Sequence[Image.Image],
    *,
    conf: float = 0.25,
    imgsz: int = 224,
    device: Optional[str] = None,
    save_debug: Optional[str | Path] = None,
    iou_threshold: float = 0.50,
) -> List[CandidateTopFaces]:
    """Run a YOLO-like model on already-cropped candidate PIL images."""
    kwargs: Dict[str, Any] = {"imgsz": imgsz, "conf": conf, "verbose": False}
    if device:
        kwargs["device"] = device
    if save_debug:
        kwargs.update({"save": True, "project": str(save_debug), "name": "predict_candidates", "exist_ok": True})
    results = model.predict(source=list(candidate_images), **kwargs)
    return [result_to_candidate_faces(i, result, iou_threshold=iou_threshold) for i, result in enumerate(results)]


def predict_strip_with_model(
    model: Any,
    image_path: str | Path,
    *,
    target_number: Optional[int] = None,
    conf: float = 0.25,
    imgsz: int = 224,
    device: Optional[str] = None,
    save_debug: Optional[str | Path] = None,
    iou_threshold: float = 0.50,
) -> Dict[str, Any]:
    """Predict all 12 candidate sums from a full dice captcha strip."""
    image_path = Path(image_path)
    layout = DiceLayout()
    img = open_rgb(image_path)
    layout.validate_image_size(img)
    candidates_img = crop_candidates(img, layout)
    candidates = predict_candidates_with_model(
        model,
        candidates_img,
        conf=conf,
        imgsz=imgsz,
        device=device,
        save_debug=save_debug,
        iou_threshold=iou_threshold,
    )

    if target_number is None:
        result: Dict[str, Any] = {
            "target_number": None,
            "candidate_sums": {c.index: c.total for c in candidates},
            "matches": [],
            "answer_index": None,
            "status": "no_target",
        }
    else:
        result = solve_from_candidate_faces(int(target_number), candidates)

    result.update({
        "image": str(image_path.resolve()),
        "candidate_count": len(candidates),
        "candidates": [c.to_dict() for c in candidates],
    })
    return result


def load_yolo_model(weights: str | Path) -> Any:
    """Lazy-load Ultralytics YOLO so unit tests do not require importing it."""
    from ultralytics import YOLO

    return YOLO(str(weights))


def predict_strip(
    image_path: str | Path,
    weights: str | Path,
    *,
    target_number: Optional[int] = None,
    conf: float = 0.25,
    imgsz: int = 224,
    device: Optional[str] = None,
    save_debug: Optional[str | Path] = None,
    iou_threshold: float = 0.50,
) -> Dict[str, Any]:
    model = load_yolo_model(weights)
    return predict_strip_with_model(
        model,
        image_path,
        target_number=target_number,
        conf=conf,
        imgsz=imgsz,
        device=device,
        save_debug=save_debug,
        iou_threshold=iou_threshold,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Infer dice top-face sums from a 2400x400 FunCaptcha strip")
    parser.add_argument("--image", required=True, help="Full 2400x400 captcha image")
    parser.add_argument("--weights", required=True, help="YOLO .pt weights, e.g. runs/.../best.pt")
    parser.add_argument("--target", type=int, default=None, help="Target number from bottom-left panel; OCR is not wired yet")
    parser.add_argument("--conf", type=float, default=0.25, help="Detection confidence threshold")
    parser.add_argument("--imgsz", type=int, default=224, help="YOLO inference image size")
    parser.add_argument("--device", default=None, help="Inference device, e.g. cpu, 0, cuda:0")
    parser.add_argument("--iou", type=float, default=0.50, help="Class-agnostic duplicate suppression IoU threshold")
    parser.add_argument("--save-debug", default=None, help="Optional directory for Ultralytics debug prediction images")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args(argv)

    result = predict_strip(
        args.image,
        args.weights,
        target_number=args.target,
        conf=args.conf,
        imgsz=args.imgsz,
        device=args.device,
        save_debug=args.save_debug,
        iou_threshold=args.iou,
    )
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
