#!/bin/sh
#
# Wrapper for OraclePWGuess by patrik.karlsson@ixsecurity.com
#

JAVA=/usr/bin/java
JDBC=classes12.zip
$JAVA -cp .:$JDBC:ork.jar ork.OraclePwGuess $*
