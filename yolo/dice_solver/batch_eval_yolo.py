# -*- coding: utf-8 -*-
"""Batch-evaluate the dice FunCaptcha YOLO top-face solver.

This script is meant for quick production-readiness checks:

    full 2400x400 captcha image
    -> OCR bottom-left target number
    -> detect 5 top faces in each of 12 candidate tiles
    -> sum candidates
    -> report unique_match / multiple_matches / nearest_fallback / no_target

It reuses the existing ``yolo_topface_infer`` pipeline and adds lightweight
OpenCV template OCR for the target number.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from .layout import DiceLayout, open_rgb
from .yolo_topface_infer import load_yolo_model, predict_strip_with_model


DEFAULT_WEIGHTS = (
    r"D:\Project\Funcaptcah_token\dice_solver\runs"
    r"\topface_v7_lowconf_softft\weights\best.pt"
)


@dataclass(frozen=True)
class DigitTemplate:
    digit: int
    source: str
    mask: np.ndarray


def _normalize_mask(mask: np.ndarray, size: Tuple[int, int] = (48, 64)) -> np.ndarray:
    """Crop non-zero pixels, preserve aspect ratio, and center on a fixed canvas."""
    mask = (mask > 0).astype(np.uint8) * 255
    ys, xs = np.where(mask > 0)
    width, height = size
    canvas = np.zeros((height, width), dtype=np.uint8)
    if len(xs) == 0:
        return canvas

    crop = mask[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    h, w = crop.shape[:2]
    scale = min((width - 8) / max(1, w), (height - 8) / max(1, h))
    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
    resized = cv2.resize(crop, (nw, nh), interpolation=cv2.INTER_AREA)
    x0 = (width - nw) // 2
    y0 = (height - nh) // 2
    canvas[y0:y0 + nh, x0:x0 + nw] = resized
    return canvas


def _mask_score(a: np.ndarray, b: np.ndarray) -> float:
    """Soft IoU score for binary/anti-aliased masks."""
    aa = _normalize_mask(a).astype(np.float32) / 255.0
    bb = _normalize_mask(b).astype(np.float32) / 255.0
    inter = np.minimum(aa, bb).sum()
    union = np.maximum(aa, bb).sum()
    return float(inter / union) if union > 0 else 0.0


def build_digit_templates() -> List[DigitTemplate]:
    """Render digit templates using common Windows fonts plus OpenCV fonts."""
    templates: List[DigitTemplate] = []
    font_paths = [
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibrib.ttf",
        r"C:\Windows\Fonts\calibri.ttf",
    ]

    for font_path in font_paths:
        if not Path(font_path).exists():
            continue
        for font_size in range(40, 84, 4):
            try:
                font = ImageFont.truetype(font_path, font_size)
            except Exception:
                continue
            for digit in range(10):
                im = Image.new("L", (100, 100), 0)
                draw = ImageDraw.Draw(im)
                draw.text((10, 0), str(digit), font=font, fill=255)
                templates.append(DigitTemplate(digit, f"{Path(font_path).name}:{font_size}", np.array(im)))

    for font_id in [
        cv2.FONT_HERSHEY_SIMPLEX,
        cv2.FONT_HERSHEY_DUPLEX,
        cv2.FONT_HERSHEY_COMPLEX,
        cv2.FONT_HERSHEY_TRIPLEX,
    ]:
        for scale in [1.4, 1.6, 1.8, 2.0, 2.2]:
            for thickness in [2, 3, 4]:
                for digit in range(10):
                    canvas = np.zeros((100, 100), dtype=np.uint8)
                    cv2.putText(
                        canvas,
                        str(digit),
                        (10, 72),
                        font_id,
                        scale,
                        255,
                        thickness,
                        lineType=cv2.LINE_AA,
                    )
                    templates.append(DigitTemplate(digit, f"cv2:{font_id}:{scale}:{thickness}", canvas))

    return templates


_DIGIT_TEMPLATES: Optional[List[DigitTemplate]] = None


def _templates() -> List[DigitTemplate]:
    global _DIGIT_TEMPLATES
    if _DIGIT_TEMPLATES is None:
        _DIGIT_TEMPLATES = build_digit_templates()
    return _DIGIT_TEMPLATES


def _classify_digit(mask: np.ndarray) -> Tuple[int, float, str]:
    best_digit = -1
    best_score = -1.0
    best_source = ""
    for tmpl in _templates():
        score = _mask_score(mask, tmpl.mask)
        if score > best_score:
            best_digit = tmpl.digit
            best_score = score
            best_source = tmpl.source
    return best_digit, best_score, best_source


def recognize_target_number(
    image: Image.Image,
    *,
    min_score: float = 0.42,
    debug_dir: Optional[str | Path] = None,
    image_stem: str = "target",
) -> Dict[str, Any]:
    """Recognize the bottom-left target number using simple template OCR.

    Returns a dict with ``target`` set to int or None.
    """
    layout = DiceLayout()
    target = image.crop(layout.target_box())
    arr = np.array(target.convert("RGB"))

    # The number usually lives in the upper-middle of the target panel.
    # Cropping this area removes most cliff/texture background under the number.
    roi = arr[45:130, 0:112]
    gray = cv2.cvtColor(roi, cv2.COLOR_RGB2GRAY)
    _, th = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)
    th = cv2.morphologyEx(th, cv2.MORPH_OPEN, np.ones((2, 2), np.uint8))

    if debug_dir:
        debug_path = Path(debug_dir)
        debug_path.mkdir(parents=True, exist_ok=True)
        cv2.imwrite(str(debug_path / f"{image_stem}_target_roi_threshold.png"), th)

    num_labels, labels, stats, _ = cv2.connectedComponentsWithStats(th, 8)
    components: List[Dict[str, Any]] = []
    for idx in range(1, num_labels):
        x, y, w, h, area = [int(v) for v in stats[idx]]
        # Keep large white digit fills, drop background fragments.
        if area < 120 or h < 30 or w < 5 or y > 70:
            continue
        # Some target backgrounds contain bright vertical texture at the right
        # edge. It touches the top of the ROI and spans most of the ROI height,
        # unlike real glyph fills.
        if y <= 3 and h > 65:
            continue
        mask = ((labels == idx).astype(np.uint8) * 255)[y:y + h, x:x + w]
        digit, score, source = _classify_digit(mask)
        if score < min_score:
            continue
        components.append({
            "x": x,
            "y": y,
            "w": w,
            "h": h,
            "area": area,
            "digit": digit,
            "score": score,
            "template": source,
        })

    # Remove nested/fragment components by keeping larger boxes first.
    kept: List[Dict[str, Any]] = []
    for comp in sorted(components, key=lambda c: c["area"], reverse=True):
        cx0, cy0 = comp["x"], comp["y"]
        cx1, cy1 = cx0 + comp["w"], cy0 + comp["h"]
        duplicate = False
        for prev in kept:
            px0, py0 = prev["x"], prev["y"]
            px1, py1 = px0 + prev["w"], py0 + prev["h"]
            inter_w = max(0, min(cx1, px1) - max(cx0, px0))
            inter_h = max(0, min(cy1, py1) - max(cy0, py0))
            inter = inter_w * inter_h
            small = max(1, min(comp["w"] * comp["h"], prev["w"] * prev["h"]))
            if inter / small > 0.45:
                duplicate = True
                break
        if not duplicate:
            kept.append(comp)

    # Target values are dice sums: usually 5..30.  Prefer left-to-right top digits.
    kept = sorted(kept, key=lambda c: c["x"])
    if len(kept) > 2:
        # Choose two most digit-like large components, then restore reading order.
        kept = sorted(kept, key=lambda c: (c["h"], c["area"], c["score"]), reverse=True)[:2]
        kept = sorted(kept, key=lambda c: c["x"])

    target_value: Optional[int] = None
    if kept:
        # Try both one- and two-digit readings and choose a valid dice-sum
        # target. This handles single-digit targets (5..9) plus occasional
        # remaining background fragments.
        valid: List[Tuple[float, int, List[Dict[str, Any]]]] = []
        for start in range(len(kept)):
            for end in range(start + 1, min(len(kept), start + 2) + 1):
                subset = kept[start:end]
                text = "".join(str(c["digit"]) for c in subset)
                try:
                    candidate = int(text)
                except ValueError:
                    continue
                if 5 <= candidate <= 30:
                    avg_score = sum(float(c["score"]) for c in subset) / len(subset)
                    # Prefer higher average confidence, then real two-digit
                    # readings when confidence ties.
                    valid.append((avg_score + 0.01 * len(subset), candidate, subset))
        if valid:
            two_digit = [x for x in valid if len(x[2]) == 2]
            pool = two_digit or valid
            _, target_value, selected = max(pool, key=lambda x: x[0])
            kept = selected

    return {
        "target": target_value,
        "digits": kept,
        "component_count": len(kept),
    }


def iter_images(input_path: str | Path, pattern: str, recursive: bool) -> List[Path]:
    p = Path(input_path)
    if p.is_file():
        return [p]
    globber = p.rglob if recursive else p.glob
    return sorted(x for x in globber(pattern) if x.is_file())


def draw_visual(result: Dict[str, Any], output_path: str | Path) -> None:
    img = Image.open(result["image"]).convert("RGB")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 24)
        small = ImageFont.truetype("arial.ttf", 18)
    except Exception:
        font = ImageFont.load_default()
        small = ImageFont.load_default()

    answer = result.get("answer_index")
    sums = {int(k): v for k, v in result.get("candidate_sums", {}).items()}
    for i in range(12):
        x0, y0, x1, y1 = i * 200, 0, (i + 1) * 200, 200
        is_answer = answer == i
        color = (255, 0, 0) if is_answer else (255, 255, 0)
        width = 6 if is_answer else 2
        draw.rectangle([x0, y0, x1 - 1, y1 - 1], outline=color, width=width)
        draw.rectangle([x0 + 4, y0 + 4, x0 + 132, y0 + 34], fill=(0, 0, 0))
        draw.text((x0 + 8, y0 + 7), f"#{i} sum={sums.get(i)}", fill=color, font=small)

    status = result.get("status")
    target = result.get("target_number")
    draw.rectangle([0, 200, 680, 245], fill=(0, 0, 0))
    draw.text((10, 210), f"target={target} answer={answer} status={status}", fill=(255, 0, 0), font=font)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path, quality=95)


def evaluate_batch(
    input_path: str | Path,
    weights: str | Path,
    *,
    pattern: str = "captcha*.jpg",
    recursive: bool = False,
    limit: Optional[int] = None,
    sample: Optional[int] = None,
    seed: int = 20260709,
    conf: float = 0.35,
    imgsz: int = 224,
    iou: float = 0.50,
    device: Optional[str] = None,
    output_dir: str | Path = "dice_solver/runs/batch_eval",
    save_visuals: bool = False,
    ocr_min_score: float = 0.55,
) -> Dict[str, Any]:
    images = iter_images(input_path, pattern, recursive)
    if sample is not None and sample > 0 and sample < len(images):
        rng = random.Random(seed)
        images = rng.sample(images, sample)
        images = sorted(images)
    if limit is not None and limit > 0:
        images = images[:limit]

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    visual_dir = output_dir / "visuals"
    ocr_debug_dir = output_dir / "ocr_debug"

    model = load_yolo_model(weights)
    if device is not None:
        try:
            model.to(device)
        except Exception:
            pass

    records: List[Dict[str, Any]] = []
    full_results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    status_counts: Counter[str] = Counter()
    ocr_counts: Counter[str] = Counter()

    for idx, image_path in enumerate(images, 1):
        try:
            img = open_rgb(image_path)
            ocr = recognize_target_number(
                img,
                min_score=ocr_min_score,
                debug_dir=ocr_debug_dir if save_visuals else None,
                image_stem=image_path.stem,
            )
            target = ocr["target"]
            if target is None:
                ocr_counts["failed"] += 1
            else:
                ocr_counts["ok"] += 1

            result = predict_strip_with_model(
                model,
                image_path,
                target_number=target,
                conf=conf,
                imgsz=imgsz,
                iou_threshold=iou,
            )
            result["target_ocr"] = ocr
            status_counts[result["status"]] += 1

            face_counts = [len(c.get("top_faces", [])) for c in result.get("candidates", [])]
            low_conf_faces = [
                f for c in result.get("candidates", [])
                for f in c.get("top_faces", [])
                if float(f.get("confidence", 1.0)) < 0.65
            ]
            record = {
                "image": str(image_path.resolve()),
                "target": target,
                "ocr_digits": "".join(str(d["digit"]) for d in ocr.get("digits", [])),
                "ocr_min_digit_score": (
                    min((float(d["score"]) for d in ocr.get("digits", [])), default=math.nan)
                ),
                "status": result["status"],
                "answer_index": result.get("answer_index"),
                "matches": ",".join(str(x) for x in result.get("matches", [])),
                "candidate_sums": json.dumps(result.get("candidate_sums", {}), ensure_ascii=False, separators=(",", ":")),
                "face_counts": ",".join(str(x) for x in face_counts),
                "bad_face_count_candidates": ",".join(str(i) for i, n in enumerate(face_counts) if n != 5),
                "low_conf_face_count": len(low_conf_faces),
            }
            records.append(record)
            full_results.append(result)

            if save_visuals:
                draw_visual(result, visual_dir / f"{image_path.stem}_eval.jpg")

            print(f"[{idx}/{len(images)}] {image_path.name} target={target} status={result['status']} answer={result.get('answer_index')}")
        except Exception as exc:
            errors.append({"image": str(image_path), "error": f"{type(exc).__name__}: {exc}"})
            status_counts["error"] += 1
            print(f"[{idx}/{len(images)}] ERROR {image_path.name}: {type(exc).__name__}: {exc}")

    csv_path = output_dir / "summary.csv"
    json_path = output_dir / "results.json"
    report_path = output_dir / "report.json"
    fieldnames = [
        "image", "target", "ocr_digits", "ocr_min_digit_score", "status", "answer_index",
        "matches", "candidate_sums", "face_counts", "bad_face_count_candidates", "low_conf_face_count",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    json_path.write_text(json.dumps(full_results, ensure_ascii=False, indent=2), encoding="utf-8")
    report = {
        "input": str(Path(input_path).resolve()),
        "weights": str(Path(weights).resolve()),
        "image_count": len(images),
        "processed_count": len(records),
        "error_count": len(errors),
        "status_counts": dict(status_counts),
        "ocr_counts": dict(ocr_counts),
        "unique_match_rate": (
            status_counts.get("unique_match", 0) / len(records) if records else 0.0
        ),
        "output_dir": str(output_dir.resolve()),
        "summary_csv": str(csv_path.resolve()),
        "results_json": str(json_path.resolve()),
        "errors": errors,
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Batch evaluate dice YOLO solver on full captcha strips")
    parser.add_argument("--input", required=True, help="Input image file or directory")
    parser.add_argument("--weights", default=DEFAULT_WEIGHTS, help="YOLO .pt weights")
    parser.add_argument("--pattern", default="captcha*.jpg", help="Glob pattern when input is a directory")
    parser.add_argument("--recursive", action="store_true", help="Search input directory recursively")
    parser.add_argument("--limit", type=int, default=None, help="Use first N images after sorting")
    parser.add_argument("--sample", type=int, default=None, help="Randomly sample N images before limit")
    parser.add_argument("--seed", type=int, default=20260709)
    parser.add_argument("--conf", type=float, default=0.35)
    parser.add_argument("--imgsz", type=int, default=224)
    parser.add_argument("--iou", type=float, default=0.50)
    parser.add_argument("--device", default=None, help="Optional YOLO device, e.g. 0 or cpu")
    parser.add_argument("--output-dir", default=r"D:\Project\Funcaptcah_token\dice_solver\runs\batch_eval_v4")
    parser.add_argument("--save-visuals", action="store_true")
    parser.add_argument("--ocr-min-score", type=float, default=0.55)
    args = parser.parse_args(argv)

    report = evaluate_batch(
        args.input,
        args.weights,
        pattern=args.pattern,
        recursive=args.recursive,
        limit=args.limit,
        sample=args.sample,
        seed=args.seed,
        conf=args.conf,
        imgsz=args.imgsz,
        iou=args.iou,
        device=args.device,
        output_dir=args.output_dir,
        save_visuals=args.save_visuals,
        ocr_min_score=args.ocr_min_score,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
