docker compose down

for /f %%i in ('docker images -q trueshotodds_springboot_v2-app') do docker rmi -f %%i
for /f %%i in ('docker images -q redis') do docker rmi -f %%i

docker compose up -d
