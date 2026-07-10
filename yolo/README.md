# yolo 骰子题求解器

## 用法

只输出答案索引 0-11：

```powershell
python C:\Users\Qiudaoyu\Desktop\yolo\solve.py "E:\Downloads\filtered_captcha_jpg\xxx.jpg"
```

或者：

```powershell
C:\Users\Qiudaoyu\Desktop\yolo\solve.bat "E:\Downloads\filtered_captcha_jpg\xxx.jpg"
```

输出示例：

```text
1
```

这个数字就是候选图索引，范围 0-11，从左到右数，0 是第一张，1 是第二张。

## 查看详细结果

```powershell
python C:\Users\Qiudaoyu\Desktop\yolo\solve.py "xxx.jpg" --json
```

## 手动传入目标数字

如果左下角 OCR 失败，可以手动传目标：

```powershell
python C:\Users\Qiudaoyu\Desktop\yolo\solve.py "xxx.jpg" --target 25
```

## 依赖安装

```powershell
pip install -r C:\Users\Qiudaoyu\Desktop\yolo\requirements.txt
```

GitHub Actions / CPU 环境建议使用 `onnxruntime`，不要使用 `onnxruntime-gpu`。
