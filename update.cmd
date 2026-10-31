@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

title Disk Investigator - Auto-Updater from GitHub

echo =======================================================
echo     Disk Investigator - GitHub Auto-Updater Tool       
echo =======================================================
echo.

:: Detect Python Runtime
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
%PYTHON_BIN% "%~dp0update_from_github.py" %*
exit /b %ERRORLEVEL%
