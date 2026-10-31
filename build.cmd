@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

title Disk Investigator - Executable Packaging Build Tool

echo =======================================================
echo    Disk Investigator - One-Click Executable Builder    
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
echo [ERROR] No suitable Python 3.12+ installation found!
echo Please ensure Python 3.12 is installed and added to PATH.
exit /b 1

:PYTHON_FOUND
echo [*] Using Python: %PYTHON_BIN%
%PYTHON_BIN% --version
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to execute Python runtime!
    exit /b 1
)
echo.

:: 2. Check & Install PyInstaller if missing
echo [*] Checking PyInstaller...
%PYTHON_BIN% -c "import PyInstaller" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] PyInstaller not found. Installing via pip...
    %PYTHON_BIN% -m pip install --upgrade pyinstaller
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to install PyInstaller via pip.
        exit /b 1
    )
) else (
    echo [+] PyInstaller is ready.
)
echo.

:: 3. Execute build_exe.py with all passed arguments
echo [*] [1/2] Compiling disk_investigator.exe...
%PYTHON_BIN% "%~dp0build_exe.py" %*
set "BUILD_EXIT_CODE=%ERRORLEVEL%"

if %BUILD_EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] Packaging failed with exit code %BUILD_EXIT_CODE%.
    exit /b %BUILD_EXIT_CODE%
)

echo.
echo [*] [2/2] Packaging disk-investigator-setup.exe...
%PYTHON_BIN% "%~dp0build_installer.py"
set "SETUP_EXIT_CODE=%ERRORLEVEL%"

if %SETUP_EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] Installer packaging failed with exit code %SETUP_EXIT_CODE%.
    exit /b %SETUP_EXIT_CODE%
)

echo.
echo [SUCCESS] Both standalone binary and 1-Click Setup EXE are ready in project root:
echo   - disk_investigator.exe
echo   - disk-investigator-setup.exe
exit /b 0
