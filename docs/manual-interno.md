# Manual Interno — IoTmx REST API

## Arquitectura general

```
app/
├── main.py                      # FastAPI app, CORS, middleware, routers
├── config.py                    # Settings (pydantic-settings, .env)
├── database/
│   ├── __init__.py              # Engine, get_session, SessionDep
│   └── model.py                 # SQLModel table definitions (BCNF)
├── domain/
│   ├── auth/                    # E2E handshake (login, logout, renew, change-password)
│   └── <entity>/
│       ├── controller.py        # FastAPI router + endpoints
│       ├── service.py           # Lógica de negocio
│       ├── repository.py        # Queries SQL
│       └── schemas.py           # Pydantic I/O schemas
└── shared/
    ├── authorization/           # Casbin RBAC
    ├── base_domain/             # BaseTable, BaseService, BaseRepository
    ├── crypto.py                # AES-256-CBC + SHA-256 primitives
    ├── e2e/                     # E2E session middleware + Valkey session repo
    ├── middleware/auth/         # Device/application auth flows (puzzle, XMSS)
    ├── rate_limit.py            # Rate limiter (Valkey-backed)
    └── session/                 # Encrypted entity sessions (JWE para devices/apps)
```

### Separación de responsabilidades

| Capa | Responsabilidad |
|------|----------------|
| Controller | Routing, request/response parsing, auth dependency injection |
| Service | Business rules, audit logging, coordination between repositories |
| Repository | SQL queries, no business logic |
| Schema | Pydantic I/O models — never expose model fields directly |

---

## Protocolo de autenticación E2E (humanos)

La autenticación humana usa **AES-256-GCM** con derivación de claves mediante **HKDF-SHA256** y contraseñas con sal por usuario. No hay JWT.

### Flujo de login (3 pasos)

**Paso 0 — Obtener salt + nonce del servidor**

```
GET /api/v1/auth/challenge?email=usuario@ejemplo.com
→ {"salt": "<hex>", "random": "<hex>"}
```

La respuesta es siempre HTTP 200 (incluso si el email no existe) para evitar enumeración de usuarios.

**Paso 1 — Construir y enviar la solicitud de login**

```
Cliente                                     Servidor
──────                                      ────────
random2 = token_hex(32)                     (challenge: salt, random ya emitidos)
effective_hash = sha256(salt + sha256(password))
temp_key = HKDF(ikm=sha256(pw)+random, salt=salt,
                info="iotmx-temp-key-v2")[:32]
payload = AES_GCM_encrypt({"random2": random2}, temp_key)
──── POST /api/v1/auth/login ──────────────────────►
     {username, payload, random, iv}

                                effective_hash = hash_password(pw, salt)
                                temp_key = HKDF(sha256(pw)+random, salt,
                                           "iotmx-temp-key-v2")
                                random2 = AES_GCM_decrypt(payload, temp_key, iv)
                                random3 = token_hex(32)
                                session_key = HKDF(random2+random3,
                                              "iotmx-session-key-v2")
                                session_id = UUID
                                Valkey.set(session_id, {session_key, account})
                                resp = AES_GCM_encrypt({random3, session-id}, temp_key)
◄─── {payload, iv} ───────────────────────────────────

random3 = AES_GCM_decrypt(resp, temp_key, iv)["random3"]
session_key = HKDF(random2+random3, "iotmx-session-key-v2")
```

### Solicitudes posteriores

```
X-Session-ID: <session_id>
Body: {"payload": "<b64>", "iv": "<b64>"}   # AES-256-GCM con session_key, nonce 12 bytes
```

El middleware (`E2EMiddleware`) descifra el cuerpo, pasa el plaintext al handler, cifra la respuesta y la devuelve en el mismo formato envelope. AES-256-GCM valida la integridad del ciphertext — cualquier modificación resulta en 400.

### Almacenamiento de contraseñas (SEC-001)

Las contraseñas se almacenan como `sha256(salt + sha256(plain_password))` con sal aleatoria por usuario (16 bytes hex). El campo `SensitiveData.password_salt` guarda la sal; `SensitiveData.password_hash` guarda el hash compuesto. La sal es necesaria para que el servidor pueda reconstruir el `temp_key` a partir del valor que envía el cliente (`sha256(plain_password)`).

### Archivos clave

| Archivo | Rol |
|---------|-----|
| `app/shared/crypto.py` | `generate_salt`, `hash_password`, `verify_password`, `derive_temp_key` (HKDF), `derive_session_key` (HKDF), `aes_encrypt`/`aes_decrypt` (GCM) |
| `app/shared/e2e/session.py` | `E2ESessionRepository` — CRUD de sesiones en Valkey |
| `app/shared/e2e/middleware.py` | `E2EMiddleware` — descifra request, cifra response, límite de cuerpo 1 MB |
| `app/domain/auth/controller.py` | `auth_router` — `/challenge`, `/login`, `/logout`, `/renew`, `/change-password` |
| `app/domain/auth/service.py` | `LoginService` — handshake completo con HKDF + GCM |
| `app/shared/auth/service.py` | `CurrentAccountDep`, `get_current_account_from_request()` |

### Tests E2E (sin Valkey real)

Los tests usan `fakeredis.FakeAsyncValkey` inyectado mediante la variable de módulo `_session_repo_override` en `app.shared.e2e.middleware`. El conftest también sobreescribe `_get_session_repo` con un lambda que devuelve el repo fakeredis para el controlador de autenticación.

```python
# conftest.py (fragmento)
fake_redis = fakeredis.FakeAsyncValkey(decode_responses=True)
e2e_repo = E2ESessionRepository("redis://localhost:6379/0")
e2e_repo.client = fake_redis
e2e_middleware_module._session_repo_override = e2e_repo
app.dependency_overrides[_get_session_repo] = lambda: e2e_repo
```

No se requiere header especial ni bypass en los tests. El middleware funciona exactamente igual que en producción, pero con Redis en memoria.

### TTL de sesión

Configurable con `SESSION_TTL_SECONDS` (default 3600 s). La renovación (`POST /auth/renew`) emite un nuevo `session_id` con TTL fresco e invalida el anterior atómicamente.

---

## Modelo de autorización (Casbin)

### Motor

Se usa **Casbin** (Apache-2.0) con modelo RBAC. El enforcer es un singleton cacheado (`@lru_cache`).

**Archivos:**
- `app/shared/authorization/model.conf` — definición del modelo RBAC
- `app/shared/authorization/policy.csv` — matriz de permisos
- `app/shared/authorization/enforcer.py` — punto de entrada `is_allowed()`
- `app/shared/authorization/dependencies.py` — FastAPI deps: `require_read/write/delete(Resource)`

### Roles

| Rol Casbin | Origen |
|------------|--------|
| `master_admin` | administrator con `is_master=True` |
| `administrator` | administrator con `is_master=False` |
| `manager` | manager |
| `user` | user |
| `support_agent` | rol de soporte básico |
| `support_admin` | rol de soporte senior |

### Dos niveles de autorización

1. **Tipo-nivel** — Casbin decide si el rol puede hacer la acción sobre el tipo de recurso.
2. **Instancia-nivel** — el repository/SQL-view filtra las filas permitidas por el usuario concreto (e.g., un manager solo ve sus dispositivos).

### Agregar un permiso nuevo

Añadir una línea a `policy.csv`:
```csv
p, <rol>, <action>, <Recurso>
```

No es necesario reiniciar si el enforcer se recarga. Para hot-reload, llamar `get_enforcer.cache_clear()`.

---

## Esquema de base de datos

### Forma normal

Todas las tablas cumplen **BCNF**:
- No hay grupos repetidos
- Cada campo no-clave depende completamente de la clave primaria
- Sin dependencias transitivas

### Tablas principales

| Tabla | PK | Notas |
|-------|-----|-------|
| `non_critical_personal_data` | UUID | Datos públicos de persona |
| `sensitive_data` | UUID | Email, password_hash (SHA-256 hex), CURP, RFC. 1:1 con non_critical |
| `administrator` | UUID | Hereda PersonalData (XMSS state incluido) |
| `manager` | UUID | Hereda PersonalData |
| `user` | UUID | Hereda PersonalData |
| `device` | UUID | Con encryption_key para sesiones cifradas |
| `application` | UUID | Con api_key y server_key |
| `service` | UUID | FK a administrator (creador) |
| `role` | UUID | FK a service; únicos por (name, service_id) |
| `role_permission` | UUID | 1:1 con role; flags can_read/write/delete/administer |
| `user_role` | UUID | Junción user ↔ role; único por (user_id, role_id) |
| `ticket_status` | **int** | Lookup table de estados; auto-increment |
| `service_ticket` | UUID | FK a user_role, ticket_status (int), service |
| `ecosystem_ticket` | UUID | FK a manager_service, ticket_status (int) |
| `subscription_type` | UUID | Tipo de suscripción; cost: NUMERIC(10,2) |
| `user_service` | UUID | Junción user ↔ service; is_active controlado por pagos |
| `payment` | UUID | FK a user_service, subscription_type |
| `payment_history` | UUID | FK a payment; amount: NUMERIC(12,2) |
| `audit_log` | UUID | Inmutable; registra toda mutación autenticada |

### Tipos de campos monetarios

`SubscriptionType.cost` y `PaymentHistory.amount` usan `NUMERIC(precision, scale)` en la DB y `Decimal` en Python para precisión exacta. Los esquemas de respuesta los convierten a `float` para compatibilidad JSON.

### Tipos de campos XMSS

`xmss_tree_height` tiene restricción `ge=2, le=20`. `xmss_current_index` tiene `ge=0`. Estas restricciones se aplican en Pydantic (validación al escribir).

---

## Flujo de pago → activación de servicio

```
POST /api/v1/payments
  → PaymentService.create_entity()
    1. Valida UserService existe
    2. Valida SubscriptionType existe
    3. Calcula expires_at (desde el último vencimiento o desde ahora)
    4. Crea Payment
    5. Crea PaymentHistory automáticamente
    6. Fija UserService.is_active = True
    7. Commit atómico

PaymentService.check_and_update_expired(user_service_id)
  → Si el último Payment.expires_at < now: is_active = False
```

Llamar `check_all_user_subscriptions(user_id)` o `check_all_service_subscriptions(service_id)` para sincronización batch.

---

## Middleware stack

```
Request
  → CORSMiddleware
  → request_id_middleware       # añade X-Request-ID
  → E2EMiddleware               # descifra body / cifra response / valida sesión
  → TenantContextMiddleware     # inyecta tenant_id en request.state (multi-tenant)
  → Router handler
```

### E2EMiddleware (`app/shared/e2e/middleware.py`)

Rutas públicas (sin cifrado requerido): `/docs`, `/openapi.json`, `/redoc`, `/health`, `/ready`, `/api/v1/auth/login`, `/api/v1/auth/challenge`, `/api/v1/onboarding/register`, `/api/v1/onboarding/verify`.

Para el resto:
1. Si `X-Session-ID` ausente → `current_account = None`, pasa al handler (endpoints que requieren auth lo rechazan vía dependencia Casbin).
2. Si `X-Session-ID` presente → busca sesión en Valkey → descifra body → inyecta `request.state.current_account` → ejecuta handler → cifra response.
3. Si Valkey no está disponible → 503.

### Autenticación de dispositivos/aplicaciones

Los dispositivos y aplicaciones usan flujos separados (`app/shared/middleware/auth/`) con:
- **auth_rc** — autenticación por puzzle (HMAC-SHA256 con `SECRET_KEY`)
- **auth_xmss** — autenticación por firma XMSS (post-cuántica)
- **auth_manager** — selecciona el método según `AUTH_DEVICE_METHOD` / `AUTH_APPLICATION_METHOD` en settings

Las sesiones de dispositivos/aplicaciones usan JWE (`app/shared/session/security.py`, `python-jose`), independiente del protocolo E2E de humanos.

### Rate limiter

El rate limiter usa **Valkey** como backend distribuido. Cada router puede tener su propio `rate_limiter()` con límite configurable. En tests se sobreescribe vía `app.dependency_overrides`.

---

## Audit trail

`BaseService._log_audit()` registra toda mutación en `audit_log`. Los campos sensibles son excluidos por servicio:

| Servicio | Excluye además de {id, created_at, updated_at} |
|----------|------------------------------------------------|
| `SensitiveDataService` | `password_hash`, `curp`, `rfc` |
| `DeviceService` | `encryption_key` |
| `ApplicationService` | `api_key` |
| Todos los demás | nada adicional |

Para agregar exclusiones a un servicio concreto:
```python
class MyService(BaseService[...]):
    audit_excluded_fields = BaseService.audit_excluded_fields | frozenset({"mi_campo_secreto"})
```

---

## Sesiones cifradas de entidades (dispositivos/aplicaciones)

`app/shared/session/` implementa sesiones JWE para dispositivos y aplicaciones:

1. El cliente genera un `key_session` de 32 bytes aleatorios (base64url)
2. `SessionService.create_entity_session()` lo almacena cifrado en Valkey
3. `SessionService.process_encrypted_request()` verifica el HMAC y devuelve la clave

Las sesiones se almacenan con TTL configurable (`SESSION_TTL_SECONDS`).

Esto es **independiente** del protocolo E2E de humanos. Los dos sistemas coexisten.

---

## Ejecución y despliegue

### Desarrollo

```bash
cp .env.example .env       # editar con valores reales
uv run uvicorn app.main:app --reload
```

### Tests

```bash
uv run pytest --cov=app --cov-report=term-missing
```

No se requiere Valkey para los tests: la suite usa `fakeredis.FakeAsyncValkey` inyectado mediante `_session_repo_override` para todos los tests E2E. No existe ningún header de bypass — el middleware E2E funciona exactamente igual que en producción. **982 tests** pasan con cobertura del 100%.

### Bootstrap de master admin

```bash
ADMIN_EMAIL=admin@empresa.com ADMIN_PASSWORD=MiPass123! uv run python seed_admin.py
```

El script es idempotente: si el email ya existe, no hace nada.

### Variables de entorno requeridas en producción

| Variable | Descripción |
|----------|-------------|
| `DATABASE_URL` | URL de PostgreSQL |
| `SECRET_KEY` | Clave HMAC para puzzle auth de dispositivos/aplicaciones (mín. 32 bytes) |
| `ENCRYPTION_KEY` | Clave AES-256 base64 para sesiones JWE de dispositivos/aplicaciones |
| `VALKEY_URL` | URL de Valkey/Redis (sesiones E2E + rate limiting) |
| `SESSION_TTL_SECONDS` | TTL de sesiones E2E en segundos (default 3600) |
| `CORS_ORIGINS` | Lista de orígenes permitidos (JSON array) |
| `DEBUG` | `false` en producción |

En producción, si `SECRET_KEY` o `ENCRYPTION_KEY` tienen sus valores por defecto, la aplicación **no arrancará** (`ValidationError` en el inicio).

---

## Type checking

```bash
uv run pyright app
```

Configurado en `pyproject.toml` con `typeCheckingMode = "standard"`. Las advertencias sobre tipos externos (stubs faltantes, tipos `Unknown`) están suprimidas para evitar ruido de librerías sin stubs.

---

## Agregar una nueva entidad

1. Definir el modelo en `app/database/model.py` (hereda `BaseTable`)
2. Crear `app/domain/<entidad>/`:
   - `schemas.py` — Create/Update/Response Pydantic models
   - `repository.py` — hereda `BaseRepository`
   - `service.py` — hereda `BaseService`; declarar `audit_excluded_fields` si tiene campos sensibles
   - `controller.py` — hereda `FullCrudApiController`; declarar `*_dependencies` con `require_read/write/delete`
3. Registrar el router en `app/main.py`
4. Agregar permisos en `app/shared/authorization/policy.csv`
5. Escribir tests en `tests/<entidad>/`
