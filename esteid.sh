#!/bin/sh
export CLASSPATH=lib/bcpkix-jdk15on-150.jar:lib/bcprov-jdk15on-150.jar:lib/gp.jar:lib/jnasmartcardio.jar:lib/jopt-simple-4.6.jar:$CLASSPATH

java -classpath $CLASSPATH -jar esteid.jar $@