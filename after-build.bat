@echo off

set dateTime=%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%
(echo %dateTime% | find "/") && set dateTime=%date:~6,4%%date:~0,2%%date:~3,2%_%time:~0,2%%time:~3,2%
set "dateTime=%dateTime: =0%"
echo dateTime=%dateTime% 

if "%1"=="" (
set "projectName=mason_app"
) else (
set "projectName=%~1")

echo projectName=%projectName% 

if "%2"=="" (
set "PREFIX=FW_APP_"
) else (
set "PREFIX=%~2")

echo PREFIX=%PREFIX% 

xcopy  .\%projectName%.bin  .\binHistory\  /Y
if exist .\binHistory\%projectName%-%PREFIX%%dateTime%.bin ( del .\binHistory\%projectName%-%PREFIX%%dateTime%.bin )
ren .\binHistory\%projectName%.bin %projectName%-%PREFIX%%dateTime%.bin

xcopy  .\Objects\%projectName%.hex  .\  /Y
xcopy  .\Objects\%projectName%.hex  .\hexHistory\  /Y
if exist .\hexHistory\%projectName%-%PREFIX%%dateTime%.hex ( del .\hexHistory\%projectName%-%PREFIX%%dateTime%.hex )
ren .\hexHistory\%projectName%.hex %projectName%-%PREFIX%%dateTime%.hex
