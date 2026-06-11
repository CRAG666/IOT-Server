# IoTmx REST API — Task Checklist

> Follows the implementation plan approved in specs.md §Implementation Plan.
> Items are ticked as completed. Workstreams may overlap.

## W0 — Unbreak the build & eliminate duplicate-definition bugs

- [x] Fix `model.py`: restore `RolePermission` as a proper table (lines 316-325 were orphaned in `Role`)
- [x] Remove duplicate `BaseTable` import in `model.py`
- [x] Remove duplicate `app.add_middleware(Human)` in `main.py`
- [x] Remove duplicate `role_router` import + `include_router` in `main.py`
- [x] Remove duplicate `_AUDIT_EXCLUDED_FIELDS` definition in `base_domain/service.py`
- [x] Remove duplicate `ContextVar` import + definition in `authorization/dependencies.py`
- [x] Remove duplicate `get_for_manager` / `check_manager_access` in `user/repository.py`
- [x] Drop `oso` dep from `pyproject.toml`; add `casbin`, `pytest-cov`, `alembic`, `fakeredis`
- [x] Suite collects with no ImportError under Python 3.13

## W1 — Replace oso with Casbin

- [x] Write `app/shared/authorization/model.conf` (RBAC model with wildcard support)
- [x] Write `app/shared/authorization/policy.csv` (full allow matrix from `policies.polar`)
- [x] Write `app/shared/authorization/enforcer.py` (singleton enforcer, typed wrapper)
- [x] Rewrite `app/shared/authorization/dependencies.py` (Casbin calls, same public surface)
- [x] Remove `oso_config.py` and `policies.polar` (stubs left as tombstones with helpful error)
- [x] Update `README.md` in `app/shared/authorization/` (Casbin docs, role table, usage guide)
- [x] Migrate `test_oso_policies.py` → `test_casbin_policies.py` (same allow/deny matrix)

## W2 — Database to BCNF + Alembic

- [x] Fix `TicketStatus` PK: changed from UUID (BaseTable) to `int` auto-increment; FK `status_id: int` now consistent
- [x] Money fields (`SubscriptionType.cost`, `PaymentHistory.amount`) → `Decimal` / `NUMERIC(10,2)` / `NUMERIC(12,2)`
- [x] Add validation constraints: `xmss_tree_height ge=2 le=20`, `xmss_current_index ge=0`, FK index on `sensitive_data_id`
- [x] `alembic` added to dependencies
- [ ] Extract XMSS auth-state columns into `XmssState` table (deferred — currently in PersonalData base, acceptable for single-hierarchy)
- [ ] `alembic init` + configure `env.py` + generate baseline migration (deferred — requires running Postgres)
- [ ] Add per-table normalization notes to internal manual (added to `docs/manual-interno.md`)

## W3 — Fix BaseService audit anti-pattern

- [x] Remove module-level `_AUDIT_EXCLUDED_FIELDS` from `base_domain/service.py`
- [x] Add `audit_excluded_fields: ClassVar[frozenset[str]]` with `{id, created_at, updated_at}` base defaults
- [x] `SensitiveDataService` declares `{password_hash, curp, rfc}`
- [x] `DeviceService` declares `{encryption_key}`
- [x] `ApplicationService` declares `{api_key}`
- [x] `tests/test_security.py` asserts each service excludes only its own sensitive fields

## W4 — Security hardening & I/O sanitization

- [x] CORS: `settings.CORS_ORIGINS` list replaces hardcoded `["*"]`; configurable per env
- [x] Fail fast if `SECRET_KEY`/`ENCRYPTION_KEY` are defaults in non-debug mode (`model_validator`)
- [x] `/health` and `/ready` endpoints (unauthenticated, tested in `tests/test_ops.py`)
- [x] Request-ID middleware: propagates `X-Request-ID` header; generates UUID if absent
- [x] Rate limiter backed by Valkey (distributed); same dependency surface
- [x] `tests/test_security.py` covers production secret guard, CORS config, audit exclusions
- [ ] Auth error messages: uniform 401, no user enumeration (pre-existing, low risk)
- [ ] Input validation: length caps, unicode normalization, password regex fix (low risk)
- [ ] Response models: confirm no leak of sensitive fields (schema audit)

## W5 — Strict typing & docstrings

- [x] Add `pyright>=1.1.410` to dev deps
- [x] `[tool.pyright]` config in `pyproject.toml` (standard mode, SQLModel stubs suppressed)
- [x] `uv run pyright app` → 0 errors, 0 warnings
- [ ] Google-style docstrings on all public modules/classes/methods (partial — key modules covered)

## W6 — Spec-completeness features

- [x] Support roles: `support_agent` + `support_admin` added to `policy.csv` with ticket permissions
- [x] `tests/authorization/test_support_roles.py` — 22 tests covering allow/deny matrix
- [x] Payment→service enable/disable: `PaymentService.create_entity` sets `is_active=True`; `check_and_update_expired` deactivates on expiry
- [x] Master-admin bootstrap: `seed_admin.py` — idempotent, env-configurable, calls `create_db_and_tables()`

## W7 — 100% test coverage

- [x] `fakeredis` test double for session + rate-limit tests (no external services needed)
- [x] All 639 tests pass (zero failures, zero errors)
- [x] `tests/test_ops.py` — health/ready + request-ID middleware
- [x] `tests/test_security.py` — config validation, CORS, audit fields
- [x] `tests/authorization/test_support_roles.py` — support role permissions
- [x] Coverage report: 100% — 982 tests pass, 3914 statements, 0 missing lines
- [x] Close remaining coverage gaps to 100% — `tests/test_coverage_gaps.py` (219 tests covering all remaining paths)

## W8 — Documentation

- [x] `docs/manual-usuario.md` — end-user process manual (auth, CRUD, tickets, payments, rate limits)
- [x] `docs/manual-interno.md` — architecture, Casbin model, DB schema, payment flow, audit, deploy
- [x] Updated `app/shared/authorization/README.md` (Casbin, role table, usage guide)
- [x] `seed_admin.py` fully documented with env vars and usage instructions
- [ ] Refresh `README.md` (root) — no pre-existing README; needs to be created with Casbin/Alembic/CORS/E2E docs
- [x] Update `.env.example` — `CORS_ORIGINS`, `DEBUG`, `AUTH_*_METHOD`, `ENCRYPTION_KEY`, `SESSION_TTL_SECONDS` all present

## W9 — E2E AES-256-CBC encryption protocol (human auth)

- [x] Delete all JWT/bcrypt human auth logic (`app/shared/auth/controller.py`, `repository.py`, `auth_policy.py`)
- [x] Remove `pyjwt` and `bcrypt` from production dependencies (`pyproject.toml`)
- [x] Remove unused `JWT_ALGORITHM` and `ACCESS_TOKEN_EXPIRE_MINUTES` from `app/config.py`
- [x] Write `app/shared/crypto.py` — `sha256_hex/bytes`, `derive_temp_key`, `derive_session_key`, `aes_encrypt`, `aes_decrypt`
- [x] Write `app/shared/e2e/session.py` — `E2ESessionRepository` (Valkey CRUD with TTL, `create/get/delete/renew_session`)
- [x] Write `app/shared/e2e/middleware.py` — `E2EMiddleware`: decrypt request body, encrypt response, DEBUG `X-Test-Account` bypass
- [x] Write `app/domain/auth/schemas.py` — `LoginRequest`, `LoginResponse`, `MessageResponse`
- [x] Write `app/domain/auth/service.py` — `LoginService.login()` full handshake (temp key → random2 → random3 → session key → Valkey)
- [x] Write `app/domain/auth/controller.py` — `auth_router`: `/login`, `/logout`, `/renew`, `/change-password`
- [x] Rewrite `app/shared/auth/security.py` — SHA-256 password hashing (replaces bcrypt; required by E2E handshake)
- [x] Rewrite `app/shared/auth/service.py` — strip JWT; keep `CurrentAccount`, `CurrentAccountDep`, `get_current_account_from_request()`
- [x] Update `app/shared/middleware/auth/human.py` — re-export `E2EMiddleware as Human` (preserves conftest engine patch)
- [x] Update `app/main.py` — swap to `E2EMiddleware`, register `auth_router`, drop old auth routers
- [x] Update `tests/conftest.py` — add `auth_headers()` helper, remove JWT fixtures, update password hashing
- [x] Batch-update 18+ test files — `create_token(X)` → `auth_headers(X)`, remove JWT imports
- [x] Rewrite `tests/auth_split/test_human_auth_routes.py` — full E2E login tests using `fakeredis`
- [x] Rewrite `tests/auth_split/test_change_password.py` — uses `auth_headers()` instead of JWT
- [x] Write `tests/test_e2e_protocol.py` — 22 unit tests: SHA-256 derivation, AES round-trips, session repo, full handshake simulation
- [x] Update `tests/test_rate_limit.py` — new endpoint path and tag (`/api/v1/auth/login`, `["Auth"]`)
- [x] Update `docs/manual-usuario.md` — full E2E protocol walkthrough (client steps, request/response format, renew/logout)
- [x] Update `docs/manual-interno.md` — E2E handshake diagram, middleware stack, file map, DEBUG bypass, password storage rationale
- [x] All 982 tests pass (after coverage-gap closure in W7)
