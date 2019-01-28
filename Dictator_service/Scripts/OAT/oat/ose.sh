#!/bin/sh
#
# Wrapper for OracleSysExec by patrik.karlsson@ixsecurity.com
#

JAVA=/usr/bin/java
JDBC=classes12.zip
$JAVA -cp .:$JDBC:ork.jar ork.OracleSysExec $*
