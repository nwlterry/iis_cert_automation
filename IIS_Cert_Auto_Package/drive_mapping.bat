@echo off
REM Map F: using machine account; persistent so task can re-run if needed
net use F: \\labwinadm01\ACME_Share /persistent:yes
exit /b %ERRORLEVEL%
