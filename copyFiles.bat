@echo off
if not exist "C:\scripts\TLS" md "C:\scripts\TLS"
if not exist "C:\scripts\TLS\backup" md "C:\scripts\TLS\backup"
xcopy "%~dp0*.*" "C:\scripts\TLS" /Y /E /C /Q /H /S