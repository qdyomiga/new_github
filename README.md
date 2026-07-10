# Battle.net FunCaptcha Register Toolkit

包含：

- `register.py`：Battle.net 注册主脚本，优先使用本地骰子 ONNX 求解，失败/非骰子题可用 CapMonster 兜底。
- `captcha_image_collector.py`：CDP 图片抓取工具。
- `register_capture_images.py`：批量抓取 FunCaptcha 图片用于训练。
- `yolo/`：本地骰子求解器与 ONNX 模型。
- `.github/workflows/register.yml`：GitHub Actions 注册工作流。
- `.github/workflows/capture-images.yml`：GitHub Actions 抓图工作流。

## 本地运行

```powershell
pip install -r requirements.txt
python -m cloakbrowser install
python register.py
```

## GitHub Actions

在 Actions 页面手动运行 `Battle.net auto register (CloakBrowser)`。

- `capmonster_key`：可选，作为非骰子/本地失败时兜底。
- `count`：运行数量。
- `max_parallel`：最大并发。

注意：不要把 `registered_account.txt`、`captcha_solve_debug/`、截图、API Key 提交到公开仓库。
