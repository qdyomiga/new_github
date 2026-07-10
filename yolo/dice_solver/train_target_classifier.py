# -*- coding: utf-8 -*-
"""Train a small CNN target-number classifier and export ONNX.

CSV format:
    image,label,source
    images/foo_target.jpg,22,...

Labels must be integers 5..30.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import random
from pathlib import Path
from typing import List, Tuple

import numpy as np
from PIL import Image, ImageEnhance, ImageOps

from .target_model_ocr import INPUT_HEIGHT, INPUT_WIDTH, TARGET_VALUES, preprocess_target_image


class TargetDataset:
    def __init__(self, root: Path, rows: List[Tuple[str, int]], augment: bool = False):
        self.root = root
        self.rows = rows
        self.augment = augment

    def __len__(self):
        return len(self.rows)

    def _augment(self, img: Image.Image) -> Image.Image:
        if not self.augment:
            return img
        if random.random() < 0.6:
            img = ImageEnhance.Contrast(img).enhance(random.uniform(0.75, 1.35))
        if random.random() < 0.6:
            img = ImageEnhance.Brightness(img).enhance(random.uniform(0.80, 1.25))
        if random.random() < 0.35:
            img = img.rotate(random.uniform(-2.0, 2.0), resample=Image.Resampling.BILINEAR, fillcolor=(0, 0, 0))
        return img

    def __getitem__(self, idx: int):
        import torch
        rel, label = self.rows[idx]
        img = Image.open(self.root / rel).convert("RGB")
        img = self._augment(img)
        arr = preprocess_target_image(img)[0]
        x = torch.from_numpy(arr)
        y = torch.tensor(TARGET_VALUES.index(label), dtype=torch.long)
        return x, y


class SmallTargetCNN:
    @staticmethod
    def build(num_classes: int = 26):
        import torch.nn as nn
        return nn.Sequential(
            nn.Conv2d(1, 16, 3, padding=1), nn.BatchNorm2d(16), nn.ReLU(inplace=True), nn.MaxPool2d(2),
            nn.Conv2d(16, 32, 3, padding=1), nn.BatchNorm2d(32), nn.ReLU(inplace=True), nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1), nn.BatchNorm2d(64), nn.ReLU(inplace=True), nn.MaxPool2d(2),
            nn.Conv2d(64, 128, 3, padding=1), nn.BatchNorm2d(128), nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d((1, 1)), nn.Flatten(), nn.Dropout(0.20), nn.Linear(128, num_classes),
        )


def load_rows(data_dir: Path) -> List[Tuple[str, int]]:
    csv_path = data_dir / "labels.csv"
    rows: List[Tuple[str, int]] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            image = (row.get("image") or "").strip()
            label_s = (row.get("label") or "").strip()
            if not image or not label_s:
                continue
            label = int(label_s)
            if label not in TARGET_VALUES:
                raise ValueError(f"invalid label {label} for {image}; expected 5..30")
            if not (data_dir / image).exists():
                raise FileNotFoundError(data_dir / image)
            rows.append((image, label))
    return rows


def split_rows(rows: List[Tuple[str, int]], val_ratio: float, seed: int):
    random.Random(seed).shuffle(rows)
    n_val = max(1, int(len(rows) * val_ratio)) if len(rows) >= 5 else 0
    return rows[n_val:], rows[:n_val]


def evaluate(model, loader, device):
    import torch
    model.eval()
    correct = 0
    total = 0
    loss_sum = 0.0
    criterion = torch.nn.CrossEntropyLoss()
    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            logits = model(x)
            loss = criterion(logits, y)
            loss_sum += float(loss.item()) * len(y)
            pred = logits.argmax(dim=1)
            correct += int((pred == y).sum().item())
            total += len(y)
    return {"loss": loss_sum / max(1, total), "acc": correct / max(1, total), "total": total}


def train(args) -> dict:
    import torch
    from torch.utils.data import DataLoader

    data_dir = Path(args.data)
    rows = load_rows(data_dir)
    if len(rows) < 20:
        raise ValueError(f"too few labeled samples: {len(rows)}; suggest >= 100")
    train_rows, val_rows = split_rows(rows[:], args.val_ratio, args.seed)
    train_ds = TargetDataset(data_dir, train_rows, augment=True)
    val_ds = TargetDataset(data_dir, val_rows, augment=False)
    train_loader = DataLoader(train_ds, batch_size=args.batch, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=args.batch, shuffle=False, num_workers=0) if val_rows else None

    device = torch.device(args.device if args.device else ("cuda" if torch.cuda.is_available() else "cpu"))
    model = SmallTargetCNN.build(len(TARGET_VALUES)).to(device)
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)

    best_acc = -1.0
    best_state = None
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        total = 0
        for x, y in train_loader:
            x, y = x.to(device), y.to(device)
            optimizer.zero_grad()
            logits = model(x)
            loss = criterion(logits, y)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item()) * len(y)
            total += len(y)
        train_loss = total_loss / max(1, total)
        val = evaluate(model, val_loader, device) if val_loader else {"loss": 0.0, "acc": 0.0, "total": 0}
        history.append({"epoch": epoch, "train_loss": train_loss, "val": val})
        print(f"Epoch {epoch}/{args.epochs} train_loss={train_loss:.4f} val_acc={val['acc']:.4f} val_loss={val['loss']:.4f}")
        score = val["acc"] if val_loader else -train_loss
        if score > best_acc:
            best_acc = score
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state:
        model.load_state_dict(best_state)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pt_path = output.with_suffix(".pt")
    torch.save({"state_dict": model.state_dict(), "target_values": TARGET_VALUES, "input": [1, INPUT_HEIGHT, INPUT_WIDTH]}, pt_path)

    model.eval().cpu()
    dummy = torch.zeros(1, 1, INPUT_HEIGHT, INPUT_WIDTH, dtype=torch.float32)
    # New PyTorch ONNX exporter prints Unicode status marks on Windows; suppress
    # them so GBK consoles do not break export after training has completed.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        torch.onnx.export(
            model,
            dummy,
            output,
            input_names=["target"],
            output_names=["logits"],
            dynamic_axes={"target": {0: "batch"}, "logits": {0: "batch"}},
            opset_version=18,
            external_data=False,
        )

    summary = {
        "data": str(data_dir.resolve()),
        "train_count": len(train_rows),
        "val_count": len(val_rows),
        "onnx": str(output.resolve()),
        "pt": str(pt_path.resolve()),
        "best_score": best_acc,
        "history": history[-5:],
    }
    output.with_suffix(".summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Train target-number classifier")
    parser.add_argument("--data", required=True, help="Dataset dir created by prepare_target_dataset.py")
    parser.add_argument("--output", default=str(Path(__file__).resolve().parents[1] / "models" / "target_classifier.onnx"))
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--val-ratio", type=float, default=0.18)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--device", default="", help="cuda/cpu; default auto")
    args = parser.parse_args()
    summary = train(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
