@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

title Disk Investigator - Remote Publisher

echo =======================================================
echo    Disk Investigator - One-Click Remote Publisher      
echo =======================================================
echo.

:: 1. Detect Python Runtime
set "PYTHON_BIN="

if exist "D:\Python-3-12\python.exe" (
    set "PYTHON_BIN=D:\Python-3-12\python.exe"
    goto :PYTHON_FOUND
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_BIN=python"
    goto :PYTHON_FOUND
)

where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_BIN=py -3.12"
    goto :PYTHON_FOUND
)

:PYTHON_NOT_FOUND
echo [ERROR] No suitable Python installation found!
exit /b 1

:PYTHON_FOUND
:: 2. Check GitHub CLI
where gh >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] GitHub CLI gh is not installed or not in PATH!
    echo Please install it via: winget install GitHub.cli
    exit /b 1
)

:: 3. Run publish_release.py
%PYTHON_BIN% "%~dp0publish_release.py" %*
exit /b %ERRORLEVEL%
