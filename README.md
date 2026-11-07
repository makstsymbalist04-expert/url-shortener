# URL Shortener

FastAPI + async SQLAlchemy + PostgreSQL + Pydantic + Alembic.
OAuth2 Authorization Code flow с обязательным PKCE S256; пароли — Argon2id.

## Быстрый запуск

Нужен Docker Desktop с Compose:

```bash
docker compose up --build
```

Открыть http://localhost:8000/docs
Миграции применяются автоматически при старте контейнера API.

`expires_at` передаётся с часовым поясом: `2027-01-01T00:00:00Z`.
`expires_at` и `max_clicks` можно не указывать или передать null.

## Локальный запуск без контейнера API

Python 3.12+, PostgreSQL (можно запустить только `docker compose up -d db`).

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
# Скопировать .env.example в .env; при необходимости изменить DATABASE_URL.
python -m alembic upgrade head
python -m uvicorn app.main:app --reload
```

## API и правила

| Метод | Путь | Результат |
|---|---|---|
| POST | /auth/register | Регистрация обычного пользователя, 201; повтор имени — 409 |
| GET/POST | /auth/authorize | Форма входа, выдача одноразового authorization code |
| POST | /auth/token | Обмен кода и PKCE verifier на Bearer token |
| GET | /auth/me | Текущий пользователь |
| POST | /links | Создание — 201; активный дубликат своего URL — 200 с прежним code |
| GET | /links | Свои неудалённые ссылки, включая истёкшие и исчерпанные |
| DELETE | /links/{id} | Soft delete своей ссылки — 204; чужая/отсутствующая — 404 |
| GET | /{code} | 302 + увеличение clicks; истёкшая/исчерпанная — 419; удалённая/отсутствующая — 404 |

Активная ссылка: `deleted_at IS NULL`, срок не истёк, число кликов меньше лимита.
Это условие определено только в `Link.active()` и используется при создании, подсчёте и редиректе.
Предел обычного пользователя — 3 активные ссылки, premium — 5; превышение — 403.
Дубликат возвращается до проверки лимита. Параметры существующей ссылки при этом не меняются.
URL нормализуется Pydantic HttpUrl; разрешены HTTP/HTTPS. Новую уже истёкшую ссылку создать можно,
но она сразу неактивна и отдаёт 419. Лимит кликов должен быть положительным.

Роль назначает администратор через БД; регистрация не позволяет самостоятельно получить premium:

```bash
docker compose exec db psql -U shortener -d shortener -c "UPDATE users SET role='premium' WHERE username='maxim';"
```

## Конкурентные запросы

- Редирект: `UPDATE links SET clicks = clicks + 1 WHERE ...active... RETURNING original_url`.
  Проверка лимита и увеличение — одна атомарная операция. При max_clicks=3 из 15 одновременных
  запросов только три получают 302, остальные — 419.
- Создание блокирует строку владельца (`SELECT FOR UPDATE`): два запроса не создадут
  дубликат и не превысят общий лимит. Пользователи не блокируют друг друга.
- PostgreSQL `clock_timestamp()` учитывает реальное время после ожидания блокировки.
- Код OAuth потребляется через `DELETE ... RETURNING`: повторный обмен невозможен.
- Каждая операция выполняется в транзакции, ошибка откатывает изменения.

## Аутентификация

Это Authorization Code flow, а не Password Grant. Публичный клиент регистрируется конфигурацией:
`OAUTH_CLIENT_ID` и точный `OAUTH_REDIRECT_URI`. Swagger использует PKCE S256.
Клиент передаёт случайный state и проверяет его при callback (Swagger делает это сам).
На форме входа есть CSRF cookie + hidden token. Код действует 5 минут, Bearer token — 1 час.
В БД сохраняются только SHA-256 хэши случайных кодов и токенов; пароли хэшируются Argon2id.
Хэширование вынесено в threadpool, чтобы не блокировать async event loop.

Для публикации за пределами локальной машины нужны HTTPS, `SECURE_COOKIES=true`,
точный HTTPS callback и отдельные секреты PostgreSQL.
## Тесты (на настоящем PostgreSQL)

Создать отдельную БД — тесты пересоздают таблицы только в ней:

```bash
docker compose up -d db
docker compose exec db createdb -U shortener shortener_test
```

PowerShell:

```powershell
$env:TEST_DATABASE_URL='postgresql+asyncpg://shortener:shortener@localhost:5432/shortener_test'
python -m pytest -q
```

Linux/macOS:

```bash
TEST_DATABASE_URL=postgresql+asyncpg://shortener:shortener@localhost:5432/shortener_test python -m pytest -q
```

Имя тестовой БД обязано оканчиваться на `_test`, URL не должен совпадать с DATABASE_URL.
Тесты проверяют роли, дубликаты, владение, soft delete, истечение срока, лимиты, конкуренцию,
валидацию, Argon2id, OAuth code flow, PKCE, CSRF и запрет повторного обмена кода.
В GitHub Actions дополнительно проверяются миграции и Ruff.

## Структура

- `app/models.py` — ORM-модели и единое условие активности.
- `app/schemas.py` — Pydantic-схемы входа/выхода.
- `app/db.py` — async engine, session, транзакции.
- `app/auth.py` — регистрация, OAuth endpoints и current_user.
- `app/main.py` — API ссылок и зависимость own_link.
- `alembic/versions/0001_initial.py` — начальная миграция.
- `tests/test_api.py` — интеграционные тесты PostgreSQL.
