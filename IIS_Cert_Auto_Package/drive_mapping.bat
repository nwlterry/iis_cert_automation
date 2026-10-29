@echo off
REM Map a drive with the machine account. No password is accepted on the command line.
REM Usage: drive_mapping.bat DRIVE UNC
REM Example: drive_mapping.bat F: \\fileserver.example\Share
if "%~1"=="" (
    echo Usage: drive_mapping.bat DRIVE UNC
    exit /b 2
)
if "%~2"=="" (
    echo UNC path is required as the second argument.
    exit /b 2
)
echo %~2 | findstr /i /c:"*" /c:"?" /c:"&" /c:"|" /c:">" /c:"<" >nul
if not errorlevel 1 (
    echo Refusing UNC path with shell metacharacters.
    exit /b 2
)
net use %~1 %~2 /persistent:yes
exit /b %ERRORLEVEL%
