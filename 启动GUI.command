#!/bin/bash
# macOS 双击启动脚本 - Web版

cd "$(dirname "$0")"
echo "正在启动加密系统 Web 界面..."
python3 web_gui.py
