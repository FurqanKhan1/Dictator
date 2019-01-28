#!/bin/sh
#
# Wrapper for OracleTNSCtrl by patrik.karlsson@ixsecurity.com
#

JAVA=/usr/bin/java
JDBC=classes12.zip
$JAVA -cp .:$JDBC:ork.jar ork.OracleTNSCtrl $*
