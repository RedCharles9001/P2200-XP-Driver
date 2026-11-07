@echo off
"%SystemRoot%\System32\cscript.exe" //nologo "%~dp0Install-Rebuilt-XP.vbs"
set "install_result=%errorlevel%"
if not "%install_result%"=="0" pause
exit /b %install_result%
