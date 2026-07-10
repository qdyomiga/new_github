# -*- coding: utf-8 -*-
"""GUI labeler for target-number dataset.

Usage:
    cd "D:/Project/GitHub_Project/Demo_Action/yolo"
    python -m dice_solver.label_target_dataset --data "D:/Project/GitHub_Project/Demo_Action/yolo/target_dataset_v1"

Controls:
    - Type target number 5..30, press Enter to save and go next.
    - S: skip current image
    - A / Left: previous
    - D / Right: next
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List

from PIL import Image, ImageTk

FIELDNAMES = ["image", "label", "source"]


def read_rows(csv_path: Path) -> List[Dict[str, str]]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append({
                "image": (row.get("image") or "").strip(),
                "label": (row.get("label") or "").strip(),
                "source": (row.get("source") or "").strip(),
            })
        return rows


def write_rows(csv_path: Path, rows: List[Dict[str, str]]) -> None:
    tmp = csv_path.with_suffix(".tmp.csv")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(csv_path)


def fit_image(img: Image.Image, max_w: int, max_h: int) -> Image.Image:
    img = img.convert("RGB")
    scale = min(max_w / img.width, max_h / img.height)
    scale = max(1.0, scale) if img.width <= max_w and img.height <= max_h else scale
    size = (max(1, int(img.width * scale)), max(1, int(img.height * scale)))
    return img.resize(size, Image.Resampling.LANCZOS)


def first_unlabeled(rows: List[Dict[str, str]]) -> int:
    for i, row in enumerate(rows):
        if not (row.get("label") or "").strip():
            return i
    return 0


class TargetLabeler:
    def __init__(self, data_dir: Path):
        import tkinter as tk
        from tkinter import messagebox

        self.tk = tk
        self.messagebox = messagebox
        self.data_dir = data_dir
        self.csv_path = data_dir / "labels.csv"
        if not self.csv_path.exists():
            raise FileNotFoundError(self.csv_path)
        self.rows = read_rows(self.csv_path)
        if not self.rows:
            raise ValueError(f"empty labels.csv: {self.csv_path}")
        self.index = first_unlabeled(self.rows)
        self.target_photo = None
        self.source_photo = None

        self.root = tk.Tk()
        self.root.title(f"Target 标注 - {self.csv_path}")
        self.root.geometry("1100x860")

        self.progress_var = tk.StringVar()
        self.path_var = tk.StringVar()
        self.source_var = tk.StringVar()
        self.label_var = tk.StringVar()
        self.status_var = tk.StringVar(value="输入数字 5-30，然后回车")

        top = tk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=8)
        tk.Label(top, textvariable=self.progress_var, font=("Consolas", 13, "bold")).pack(side="left")
        tk.Label(top, textvariable=self.status_var, fg="#0a6", font=("Microsoft YaHei UI", 11)).pack(side="right")

        self.target_label = tk.Label(self.root, bg="#222")
        self.target_label.pack(padx=10, pady=6)

        form = tk.Frame(self.root)
        form.pack(fill="x", padx=10, pady=8)
        tk.Label(form, text="这个 target 数字是：", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.entry = tk.Entry(form, textvariable=self.label_var, font=("Consolas", 22), width=5, justify="center")
        self.entry.pack(side="left", padx=8)
        self.entry.bind("<Return>", lambda e: self.save_next())
        tk.Button(form, text="保存并下一张(Enter)", command=self.save_next, font=("Microsoft YaHei UI", 11)).pack(side="left", padx=6)
        tk.Button(form, text="跳过(S)", command=self.skip, font=("Microsoft YaHei UI", 11)).pack(side="left", padx=6)
        tk.Button(form, text="上一张(A)", command=self.prev, font=("Microsoft YaHei UI", 11)).pack(side="left", padx=6)
        tk.Button(form, text="下一张(D)", command=self.next, font=("Microsoft YaHei UI", 11)).pack(side="left", padx=6)

        tk.Label(self.root, text="原始整图预览（辅助确认）：", font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=10)
        self.source_label = tk.Label(self.root, bg="#111")
        self.source_label.pack(padx=10, pady=6)

        info = tk.Frame(self.root)
        info.pack(fill="x", padx=10, pady=4)
        tk.Label(info, textvariable=self.path_var, anchor="w", justify="left", font=("Consolas", 9)).pack(fill="x")
        tk.Label(info, textvariable=self.source_var, anchor="w", justify="left", font=("Consolas", 9)).pack(fill="x")

        self.root.bind("s", lambda e: self.skip())
        self.root.bind("S", lambda e: self.skip())
        self.root.bind("a", lambda e: self.prev())
        self.root.bind("A", lambda e: self.prev())
        self.root.bind("<Left>", lambda e: self.prev())
        self.root.bind("d", lambda e: self.next())
        self.root.bind("D", lambda e: self.next())
        self.root.bind("<Right>", lambda e: self.next())
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.render()
        self.entry.focus_set()

    def current(self) -> Dict[str, str]:
        return self.rows[self.index]

    def counts(self):
        labeled = sum(1 for r in self.rows if (r.get("label") or "").strip())
        return labeled, len(self.rows)

    def render(self):
        row = self.current()
        labeled, total = self.counts()
        self.progress_var.set(f"{self.index + 1}/{total}    已标注 {labeled}/{total}")
        self.label_var.set(row.get("label", ""))
        self.path_var.set(f"target: {self.data_dir / row['image']}")
        self.source_var.set(f"source: {row.get('source', '')}")

        target_path = self.data_dir / row["image"]
        try:
            img = Image.open(target_path).convert("RGB")
            img = fit_image(img, 520, 520)
            self.target_photo = ImageTk.PhotoImage(img)
            self.target_label.configure(image=self.target_photo, text="")
        except Exception as e:
            self.target_label.configure(image="", text=f"打开 target 失败: {e}", fg="red")

        src = row.get("source") or ""
        try:
            if src and Path(src).exists():
                simg = Image.open(src).convert("RGB")
                simg = fit_image(simg, 1040, 210)
                self.source_photo = ImageTk.PhotoImage(simg)
                self.source_label.configure(image=self.source_photo, text="")
            else:
                self.source_label.configure(image="", text="无 source 预览", fg="white")
        except Exception as e:
            self.source_label.configure(image="", text=f"打开 source 失败: {e}", fg="red")

        self.entry.focus_set()
        self.entry.select_range(0, "end")

    def save(self) -> bool:
        value = self.label_var.get().strip()
        try:
            n = int(value)
        except Exception:
            self.status_var.set("❌ 请输入 5-30 的数字")
            return False
        if not 5 <= n <= 30:
            self.status_var.set("❌ 只允许 5-30")
            return False
        self.rows[self.index]["label"] = str(n)
        write_rows(self.csv_path, self.rows)
        self.status_var.set(f"✅ 已保存: {n}")
        return True

    def save_next(self):
        if self.save():
            self.next()

    def skip(self):
        self.status_var.set("已跳过")
        self.next()

    def next(self):
        self.index = min(len(self.rows) - 1, self.index + 1)
        self.render()

    def prev(self):
        self.index = max(0, self.index - 1)
        self.render()

    def close(self):
        write_rows(self.csv_path, self.rows)
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Visual labeler for target-number labels.csv")
    parser.add_argument("--data", required=True, help="Dataset dir containing labels.csv and images/")
    args = parser.parse_args()
    TargetLabeler(Path(args.data)).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
