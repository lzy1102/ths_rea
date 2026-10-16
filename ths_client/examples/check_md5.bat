@echo off
chcp 65001 >nul
title md5 check (local only)
cd /d "%~dp0"
"D:\Program Files\Python312\python.exe" check_md5.py
