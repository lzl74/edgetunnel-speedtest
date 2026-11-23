#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键构建脚本: 将 cfspeed 打包为真正单文件独立绿色的 cfspeed.exe
无需在外部携带 cf_ranges.json, cidrs.txt 或 presets.py, 拷贝单个 exe 即可在任何 Windows 电脑运行。
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def build():
    print("==================================================")
    print("  开始打包 cfspeed 独立绿色可执行文件 ...")
    print("==================================================")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "-y",
        "-F",  # 单文件打包
        "--name", "cfspeed",
        "--add-data", f"{os.path.join(HERE, 'cf_ranges.json')};.",
        "--add-data", f"{os.path.join(HERE, 'cidrs.txt')};.",
        "--hidden-import", "presets",
        "--hidden-import", "cf_ranges",
        os.path.join(HERE, "cfspeed.py"),
    ]

    print("执行打包命令:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=HERE)
    if res.returncode != 0:
        print("打包失败!")
        return res.returncode

    exe_path = os.path.join(HERE, "dist", "cfspeed.exe")
    print("\n√ 打包成功! 单文件可执行程序已生成:")
    print(f"  {exe_path} ({os.path.getsize(exe_path) / 1024 / 1024:.2f} MB)")

    # 拷贝并更新 dist 目录中的使用说明文档
    doc_src = os.path.join(HERE, "使用说明.txt")
    doc_dst = os.path.join(HERE, "dist", "使用说明.txt")
    if os.path.exists(doc_src):
        shutil.copy2(doc_src, doc_dst)
        print(f"  √ 已同步使用说明: {doc_dst}")

    # 清理 dist 目录下多余的 .py 源码文件（过去遗留在此的混乱文件）
    for extra in ["cf_ranges.py", "cfspeed.py", "presets.py", "cidrs.txt", "cf_ranges.json"]:
        p = os.path.join(HERE, "dist", extra)
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"  - 已清理 dist 中多余的源码文件: {extra}")
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(build())
