@echo off
rem Сборка ru_patcher.exe (нужны: Python 3.10+, pip install numpy pillow pyinstaller)
pyinstaller --onefile --noconfirm --name ru_patcher --add-data "data;data" --exclude-module matplotlib --exclude-module scipy --exclude-module pandas ru_patcher.py
echo.
echo Готово: dist\ru_patcher.exe
pause
