@echo off
setlocal EnableExtensions
set "APP_DIR=%~dp0"
set "ROOT_DIR=%APP_DIR%"
set "PYTHONW=%APP_DIR%.venv\Scripts\pythonw.exe"
set "TOOL_URL=http://127.0.0.1:5033/"
set "HEALTH_URL=http://127.0.0.1:5033/api/health"

REM Standalone release: setup is complete only after every dependency and
REM pinned browser verification succeeds.
if exist "%APP_DIR%.setup-complete" if exist "%PYTHONW%" goto runtime_ready

REM Monorepo development layout: reuse the parent virtual environment only when
REM core modules are not bundled beside this launcher.
if not exist "%APP_DIR%_camoufox_runtime.py" if exist "%APP_DIR%..\.venv\Scripts\pythonw.exe" (
  set "ROOT_DIR=%APP_DIR%.."
  set "PYTHONW=%APP_DIR%..\.venv\Scripts\pythonw.exe"
  goto runtime_ready
)

REM First standalone launch: install Python dependencies and browser runtime.
if not exist "%APP_DIR%setup.bat" (
  echo [Tool Password vs 2FA GPT] Khong tim thay setup.bat trong:
  echo %APP_DIR%
  pause
  exit /b 1
)
call "%APP_DIR%setup.bat"
if errorlevel 1 (
  echo.
  echo [Tool Password vs 2FA GPT] Setup that bai. Kiem tra loi phia tren roi thu lai.
  pause
  exit /b 1
)
set "ROOT_DIR=%APP_DIR%"
set "PYTHONW=%APP_DIR%.venv\Scripts\pythonw.exe"
if not exist "%PYTHONW%" (
  echo [Tool Password vs 2FA GPT] Setup xong nhung khong tim thay pythonw.exe.
  pause
  exit /b 1
)

:runtime_ready
set "SOURCE_CA=%ROOT_DIR%\.venv\Lib\site-packages\certifi\cacert.pem"
set "ASCII_CA_DIR=%LOCALAPPDATA%\Lehaipreshop\Change2FA"
set "ASCII_CA=%ASCII_CA_DIR%\cacert.pem"

if not exist "%SOURCE_CA%" (
  echo [Tool Password vs 2FA GPT] Khong tim thay CA certificate:
  echo %SOURCE_CA%
  pause
  exit /b 1
)
if not exist "%ASCII_CA_DIR%" mkdir "%ASCII_CA_DIR%"
copy /Y "%SOURCE_CA%" "%ASCII_CA%" >nul
if errorlevel 1 (
  echo [Tool Password vs 2FA GPT] Khong the chuan bi CA certificate.
  pause
  exit /b 1
)

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "CURL_CA_BUNDLE=%ASCII_CA%"
set "SSL_CERT_FILE=%ASCII_CA%"
set "REQUESTS_CA_BUNDLE=%ASCII_CA%"

powershell -NoProfile -Command ^
  "try { if ((Invoke-RestMethod -Uri '%HEALTH_URL%' -TimeoutSec 1).ok) { exit 0 } } catch {}; exit 1"
if not errorlevel 1 goto open_tool

pushd "%ROOT_DIR%"
if not exist "%ROOT_DIR%\runtime" mkdir "%ROOT_DIR%\runtime"
start "" /b "%PYTHONW%" "%APP_DIR%server.py" --host 127.0.0.1 --port 5033 --no-browser > "%ROOT_DIR%\runtime\server.log" 2>&1
popd

powershell -NoProfile -WindowStyle Hidden -Command ^
  "for ($i=0; $i -lt 720; $i++) { try { if ((Invoke-RestMethod -Uri '%HEALTH_URL%' -TimeoutSec 1).ok) { exit 0 } } catch {}; Start-Sleep -Milliseconds 250 }; exit 1"
if errorlevel 1 (
  powershell -NoProfile -Command ^
    "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Server khong phan hoi sau 3 phut. Lan dau co the can tai Camoufox browser - thu lai hoac kiem tra log.','Lehaipreshop') | Out-Null"
  exit /b 1
)

:open_tool
if /I "%~1"=="--no-browser" exit /b 0
start "" "%TOOL_URL%"
if errorlevel 1 start "" explorer.exe "%TOOL_URL%"

endlocal
