#!/bin/sh
#
# Wrapper for OracleQuery by patrik@cqure.net
#

JAVA=/usr/bin/java
JDBC=classes12.zip
$JAVA -cp .:$JDBC:ork.jar ork.OracleQuery $*
