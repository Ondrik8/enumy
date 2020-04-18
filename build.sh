#! /bin/sh
mkdir output 2> /dev/null
rm output/enumy 2> /dev/null 
docker build -t enumy_environment -f docker/Dockerfile . 
docker container create --name enumy_temp enumy_environment 
docker container cp enumy_temp:/build/output/enumy ./output
docker container rm enumy_temp
file output/enumy
ldd output/enumy