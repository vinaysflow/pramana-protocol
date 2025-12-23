.PHONY: dev up down logs test seed

up:
	docker-compose up -d --build

logs:
	docker-compose logs -f --tail=200

down:
	docker-compose down

dev: up
	@echo "UI:  http://127.0.0.1:6080"
	@echo "API: http://127.0.0.1:5051/health"
	@echo "KC:  http://127.0.0.1:8080 (realm: pramana, user: demo-user/demo)"

# Backend tests (assumes backend/.venv exists)

test:
	cd backend && . .venv/bin/activate && pytest
