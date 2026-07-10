# -*- coding: utf-8 -*-
"""Data schema for dice top-face detection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence


VALID_LABELS = {f"top_{i}" for i in range(1, 7)}


@dataclass(frozen=True)
class TopFaceDetection:
    """One detected upward-facing dice face inside a 200x200 candidate image."""

    label: str
    value: int
    box: Sequence[float]
    confidence: float = 1.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopFaceDetection":
        label = str(data.get("label") or "")
        if label not in VALID_LABELS:
            raise ValueError(f"invalid top-face label: {label!r}")
        value = int(data.get("value") or label.rsplit("_", 1)[-1])
        if value < 1 or value > 6:
            raise ValueError(f"invalid top-face value: {value}")
        box = data.get("box") or []
        if len(box) != 4:
            raise ValueError(f"box must have four numbers: {box!r}")
        return cls(label=label, value=value, box=box, confidence=float(data.get("confidence", 1.0)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "value": self.value,
            "box": list(self.box),
            "confidence": self.confidence,
        }


@dataclass
class CandidateTopFaces:
    index: int
    top_faces: List[TopFaceDetection] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(face.value for face in self.top_faces)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CandidateTopFaces":
        return cls(
            index=int(data["index"]),
            top_faces=[TopFaceDetection.from_dict(x) for x in data.get("top_faces", [])],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "sum": self.total,
            "top_faces": [x.to_dict() for x in self.top_faces],
        }
