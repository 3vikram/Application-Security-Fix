@echo off
REM THIS BATCH FILE AUTOMATES THE PROCESS OF VERIFYING THE SIGNED JARS

REM LOCATION OF JAR FILES
set pathentry="C:\Program Files\Java\jre1.8.0_144\bin"

REM TEH CODE TO PERFORM JAR FILE SIGNED VERIFICATION
echo Adding Path Entry %pathentry%...
set path=%path%;%pathentry%
set basedir=%cd%
:menu
if not "%basedir%"=="%cd%" cd "%basedir%"
echo GotCake's Jar files sign verification:
echo 1: Verify JAR files
echo 2: Exit
set /p ans=
if %ans% equ 1 goto jar file verification
if %ans% equ 2 goto exit

:jar file verification
echo Verifying JAR files...
for /f "tokens=*" %%a in ('dir /b C:\jar files\') do jarsigner -verify *.jar
echo Done VERIFYING Jars.
goto menu

:exit