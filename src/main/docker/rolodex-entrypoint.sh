#!/bin/bash
#cp /etc/rolodex-certs/ca.crt /certs/ca.crt
#cp ca.crt /certs/ca.crt
cp config.yml /config/config.yml
#keytool -noprompt -storepass rolodex -import -alias ad -keystore adcert.jks -file /certs/ca.crt
java ${ROLODEX_JVM_OPT_ARGS}  -Ddw.partitionLoc=${PARTITIONLOC}  -Ddw.connectors=${CONNECTORS} -jar rolodex.jar server /config/config.yml
