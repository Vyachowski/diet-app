install:
	npm ci
start:
	npm run start
dev:
	npm run start:dev

format:
	npm run lint

resource:
	nest g resource $(name)
res:
	nest g resource $(name)
new:
	nest g resource $(name)
