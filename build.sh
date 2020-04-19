#! /bin/sh
make clean 2> /dev/null
mkdir output 2> /dev/null
rm output/enumy 2> /dev/null 

if [ "$1" == "32bit" ]; then
    echo "building in 32 bit mode"
    docker build -t enumy_environment -f docker/Dockerfile.32bit . 
elif [ "$1" == "64bit" ]; then
    echo "building in 64 bit mode"
    docker build -t enumy_environment -f docker/Dockerfile.64bit . 
else
    echo "USAGE:"
    echo "  ./build.sh 32bit"
    echo "  ./build.sh 64bit"
    exit
fi

docker container rm enumy_temp 
docker container create --name enumy_temp enumy_environment 
docker container cp enumy_temp:/build/output/enumy ./output
docker container rm enumy_temp
file output/enumy
ldd output/enumy