# -*- coding: utf-8 -*-
"""Prepare target-number classification dataset from 2400x400 dice strips.

Example:
    python -m dice_solver.prepare_target_dataset --input "E:/Downloads/filtered_captcha_jpg" --output "yolo/target_dataset_v1"

Then fill labels.csv: image,label  where label is 5..30.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable

from PIL import Image

from .layout import DiceLayout
from .target_model_ocr import crop_target_from_image

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp"}


def iter_images(input_dir: Path) -> Iterable[Path]:
    for path in sorted(input_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in IMAGE_EXTS:
            yield path


def is_dice_strip(path: Path) -> bool:
    try:
        with Image.open(path) as im:
            return im.size == (2400, 400)
    except Exception:
        return False


def read_existing_labels(csv_path: Path) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    if not csv_path.exists():
        return labels
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            image = (row.get("image") or "").strip()
            label = (row.get("label") or "").strip()
            if image:
                labels[image] = label
    return labels


def prepare_dataset(input_dir: Path, output_dir: Path, limit: int | None = None) -> dict:
    images_dir = output_dir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    labels_csv = output_dir / "labels.csv"
    existing = read_existing_labels(labels_csv)

    rows = []
    count = 0
    skipped_non_dice = 0
    for src in iter_images(input_dir):
        if limit is not None and count >= limit:
            break
        if not is_dice_strip(src):
            skipped_non_dice += 1
            continue
        with Image.open(src) as im:
            target = crop_target_from_image(im)
            out_name = f"{src.stem}_target.jpg"
            out_path = images_dir / out_name
            if not out_path.exists():
                target.save(out_path, quality=95)
        rel = f"images/{out_name}"
        rows.append({
            "image": rel,
            "label": existing.get(rel, ""),
            "source": str(src.resolve()),
        })
        count += 1

    with labels_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["image", "label", "source"])
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "input_dir": str(input_dir.resolve()),
        "output_dir": str(output_dir.resolve()),
        "target_images": len(rows),
        "skipped_non_dice": skipped_non_dice,
        "labels_csv": str(labels_csv.resolve()),
        "classes": "5..30",
        "next_step": "Fill labels.csv label column, then run python -m dice_solver.train_target_classifier --data <output_dir>",
    }
    (output_dir / "prepare_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Crop target number panels and create labels.csv")
    parser.add_argument("--input", required=True, help="Directory containing 2400x400 captcha jpg/png files")
    parser.add_argument("--output", required=True, help="Output dataset directory")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    summary = prepare_dataset(Path(args.input), Path(args.output), args.limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
