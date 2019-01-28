@echo off
rem
rem OracleSamDump by Patrik Karlsson <patrik.karlsson@ixsecurity.com>
rem

@set CP=.;classes111.zip;ork.jar

java -classpath %CP% ork.OracleSamDump %*