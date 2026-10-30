@echo off
chcp 65001 >nul
echo 正在打包 cfspeed.exe ...
echo.

python -m pip install pyinstaller --quiet --disable-pip-version-check
if errorlevel 1 (
    echo [错误] PyInstaller 安装失败,请检查 Python 和网络。
    pause
    exit /b 1
)

python -m PyInstaller --onefile --console --clean --noconfirm --name cfspeed cfspeed.py
if errorlevel 1 (
    echo.
    echo [错误] 打包失败。
    pause
    exit /b 1
)

echo.
echo 打包完成: dist\cfspeed.exe
pause
