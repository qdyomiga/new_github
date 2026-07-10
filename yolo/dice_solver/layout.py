# -*- coding: utf-8 -*-
"""Dice FunCaptcha layout helpers.

Observed dice strip:
- Full image: 2400x400
- Top row: 12 candidates, each 200x200
- Bottom-left target panel: about 125x200
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from PIL import Image


@dataclass(frozen=True)
class DiceLayout:
    candidate_width: int = 200
    candidate_height: int = 200
    candidate_count: int = 12
    target_width: int = 125
    target_height: int = 200

    def target_box(self) -> Tuple[int, int, int, int]:
        return (0, self.candidate_height, self.target_width, self.candidate_height + self.target_height)

    def candidate_box(self, index: int) -> Tuple[int, int, int, int]:
        if index < 0 or index >= self.candidate_count:
            raise IndexError(f"candidate index out of range: {index}")
        x0 = index * self.candidate_width
        return (x0, 0, x0 + self.candidate_width, self.candidate_height)

    def validate_image_size(self, img: Image.Image) -> None:
        min_w = self.candidate_width * self.candidate_count
        min_h = self.candidate_height + self.target_height
        if img.width < min_w or img.height < min_h:
            raise ValueError(f"expected at least {min_w}x{min_h}, got {img.width}x{img.height}")


def open_rgb(path: str | Path) -> Image.Image:
    return Image.open(path).convert("RGB")


def crop_target(img: Image.Image, layout: DiceLayout | None = None) -> Image.Image:
    layout = layout or DiceLayout()
    return img.crop(layout.target_box())


def crop_candidates(img: Image.Image, layout: DiceLayout | None = None) -> List[Image.Image]:
    layout = layout or DiceLayout()
    return [img.crop(layout.candidate_box(i)) for i in range(layout.candidate_count)]


def save_crops(image_path: str | Path, output_dir: str | Path, *, sample_id: str | None = None) -> dict:
    layout = DiceLayout()
    image_path = Path(image_path)
    output_dir = Path(output_dir)
    sample_id = sample_id or image_path.stem
    img = open_rgb(image_path)
    layout.validate_image_size(img)

    target_dir = output_dir / "targets"
    cand_dir = output_dir / "candidates" / sample_id
    target_dir.mkdir(parents=True, exist_ok=True)
    cand_dir.mkdir(parents=True, exist_ok=True)

    target_path = target_dir / f"{sample_id}_target.jpg"
    crop_target(img, layout).save(target_path, quality=95)

    candidate_paths = []
    for i, cand in enumerate(crop_candidates(img, layout)):
        path = cand_dir / f"candidate_{i}.jpg"
        cand.save(path, quality=95)
        candidate_paths.append(str(path))

    return {
        "source_image": str(image_path.resolve()),
        "target_image": str(target_path.resolve()),
        "candidate_images": candidate_paths,
        "candidate_count": len(candidate_paths),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Crop 2400x400 dice captcha into target + 12 candidates")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("crop")
    p.add_argument("--image", required=True)
    p.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.cmd == "crop":
        import json
        print(json.dumps(save_crops(args.image, args.output), ensure_ascii=False, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
