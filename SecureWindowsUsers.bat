@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"




set var=1
set loca=%~dp0
set pass="QwErTyUiOp{]|\1"
copy "%loca%AllowedUsers.txt" "%loca%AllowedUsers1.txt"

:start1
REM Set First Line User Variable
set /p user= 0<%loca%AllowedUsers.txt

REM Change Password
net user %user% %pass% /scriptpath: /workstations: /homedir: /passwordchg:yes /passwordreq:yes /active:yes /expires:never /times:all

WMIC USERACCOUNT WHERE "Name='%user%'" SET PasswordExpires=TRUE >> nul 2>&1
WMIC USERACCOUNT WHERE "Name='%user%'" SET PasswordRequired=TRUE >> nul 2>&1
WMIC USERACCOUNT WHERE "Name='%user%'" SET PasswordChangeable=TRUE >> nul 2>&1
REM Delete First Line
more +1 "%loca%AllowedUsers.txt" >"%loca%AllowedUsers.txt.new"
move /y "%loca%AllowedUsers.txt.new" "%loca%AllowedUsers.txt" >nul

if '%user%'=='%var%' (
goto end1
)

set var=%user%

goto start1
:end1
del "%loca%AllowedUsers.txt"






set var1=1

net localgroup administrators > "%loca%admins.txt"
more +6 "%loca%admins.txt" >"%loca%admins.txt.new"
move /y "%loca%admins.txt.new" "%loca%admins.txt" >nul

:disable2
REM Take first line variable
set /p var= 0<%loca%admins.txt

REM Delete First Line
more +1 "%loca%admins.txt" >"%loca%admins.txt.new"
move /y "%loca%admins.txt.new" "%loca%admins.txt" >nul

if "%var%"=="The command completed successfully." (
goto enable2
)
if "%var%"=="Administrator" (
goto disable2
)

REM Disable Account
net localgroup administrators "%var%" /delete

goto disable2
:enable2

REM Take first line variable
set /p var= 0<%loca%AllowedAdmins.txt

if '%var%'=='%var1%' (
goto done2
)

REM Delete First Line
more +1 "%loca%AllowedAdmins.txt" >"%loca%AllowedAdmins.txt.new"
move /y "%loca%AllowedAdmins.txt.new" "%loca%AllowedAdmins.txt" >nul

REM Enable Account
net localgroup administrators "%var%" /add
IF %ERRORLEVEL% NEQ 0 net user /add %var% %pass% && net localgroup administrators %var% /add

set var1=%var%


goto enable2
:done2
del "%loca%admins.txt"
del "%loca%AllowedAdmins.txt"






set var1=1

REM Retrieve All Users
net localgroup Users > "%~dp0AllUsers.txt"
more +6 "%~dp0AllUsers.txt" >"%~dp0AllUsers.txt.new"
move /y "%~dp0AllUsers.txt.new" "%~dp0AllUsers.txt" >nul

:disable3
REM Take first line variable
set /p var= 0<%~dp0AllUsers.txt

REM Delete First Line
more +1 "%~dp0AllUsers.txt" >"%~dp0AllUsers.txt.new"
move /y "%~dp0AllUsers.txt.new" "%~dp0AllUsers.txt" >nul


if "%var%"=="NT AUTHORITY\Authenticated Users" (
goto disable3
)
if "%var%"=="NT AUTHORITY\INTERACTIVE" (
goto disable3
)
if "%var%"=="defaultuser0" (
goto disable3
)
if "%var%"=="Default" (
goto disable3
)
if "%var%"=="Public" (
goto disable3
)
if "%var%"=="The command completed successfully." (
goto enable3
)

REM Disable Account
net user "%var%" /active:no

goto disable3

:enable3
REM Take first line variable
set /p var= 0<%~dp0AllowedUsers1.txt

REM Delete First Line
more +1 "%~dp0AllowedUsers1.txt" >"%~dp0AllowedUsers1.txt.new"
move /y "%~dp0AllowedUsers1.txt.new" "%~dp0AllowedUsers1.txt" >nul


REM Enable Account
net user %var% /active:yes
IF %ERRORLEVEL% NEQ 0 net user /add %var% %pass% 

if '%var%'=='%var1%' (
goto done3
)

set var1=%var%

goto enable3
:done3
del "%~dp0AllowedUsers1.txt"
del "%~dp0AllUsers.txt"
