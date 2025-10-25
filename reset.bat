docker compose down app
docker image prune -f
docker compose up --build app -d
