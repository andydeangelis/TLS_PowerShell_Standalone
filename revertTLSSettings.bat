@echo off
pushd "%~dp0"

powershell.exe -ExecutionPolicy Bypass -Command "& ./ApplyTLSRegistrySettings.ps1 -RestoreBackup"
pause