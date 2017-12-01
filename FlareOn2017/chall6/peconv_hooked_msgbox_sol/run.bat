@echo off
set loopcount=0
:loop
peconv_hooked_msgbox_sol.exe payload.dll %loopcount%
set /a loopcount=loopcount+1
if %loopcount%==26 goto exitloop
goto loop
:exitloop
echo.
pause
