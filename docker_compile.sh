docker build -t enumy_environment docker/ 
docker run -v `pwd`/output:/build/output -t enumy_environment sh docker/compile.sh