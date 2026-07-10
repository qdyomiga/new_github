# -*- coding: utf-8 -*-
"""Export target-number classifier .pt checkpoint to ONNX without retraining."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path

from .target_model_ocr import INPUT_HEIGHT, INPUT_WIDTH, TARGET_VALUES
from .train_target_classifier import SmallTargetCNN


def export_checkpoint(checkpoint: Path, output: Path) -> dict:
    import torch

    if not checkpoint.exists():
        raise FileNotFoundError(checkpoint)
    output.parent.mkdir(parents=True, exist_ok=True)

    ckpt = torch.load(checkpoint, map_location="cpu")
    model = SmallTargetCNN.build(len(TARGET_VALUES))
    state = ckpt.get("state_dict", ckpt)
    model.load_state_dict(state)
    model.eval().cpu()

    dummy = torch.zeros(1, 1, INPUT_HEIGHT, INPUT_WIDTH, dtype=torch.float32)
    # Suppress PyTorch ONNX Unicode progress output; Windows GBK terminals can
    # otherwise fail on the check-mark character even when export succeeds.
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
        "checkpoint": str(checkpoint.resolve()),
        "onnx": str(output.resolve()),
        "target_values": TARGET_VALUES,
        "input_shape": [1, 1, INPUT_HEIGHT, INPUT_WIDTH],
    }
    output.with_suffix(".export_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Export target classifier .pt to ONNX")
    parser.add_argument("--checkpoint", default=str(Path(__file__).resolve().parents[1] / "models" / "target_classifier.pt"))
    parser.add_argument("--output", default=str(Path(__file__).resolve().parents[1] / "models" / "target_classifier.onnx"))
    args = parser.parse_args()
    print(json.dumps(export_checkpoint(Path(args.checkpoint), Path(args.output)), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
