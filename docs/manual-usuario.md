# Manual de Usuario — IoTmx REST API

## Introducción

IoTmx es una plataforma multi-tenant para administración de dispositivos IoT. Este manual describe los flujos de trabajo disponibles para cada tipo de usuario y cómo interactuar con la API.

---

## Roles y permisos

| Rol | Descripción |
|-----|-------------|
| **master_admin** | Administrador raíz. Acceso irrestricto. Uno por instalación. |
| **administrator** | Gestiona usuarios, managers, dispositivos y servicios dentro de su instancia. |
| **manager** | Gestiona dispositivos y aplicaciones asignados a sus servicios. |
| **user** | Usuario final. Lee dispositivos y servicios; gestiona sus propios datos. |
| **support_agent** | Soporte técnico de lectura. Puede crear/actualizar tickets de servicio. |
| **support_admin** | Soporte senior. CRUD completo sobre tickets; lectura de usuarios y servicios. |

---

## Autenticación

La API usa un protocolo de **cifrado extremo a extremo (E2E) con AES-256-GCM** y derivación de claves **HKDF-SHA256**. No se usan tokens JWT. Todas las comunicaciones autenticadas son opacas a intermediarios.

### Inicio de sesión

El inicio de sesión requiere dos llamadas:

**Paso 1 — Obtener salt y nonce del servidor**

```
GET /api/v1/auth/challenge?email=usuario@ejemplo.com
```

Respuesta:
```json
{
  "salt": "<hex de 16 bytes>",
  "random": "<hex de 32 bytes>"
}
```

Guarde `salt` y `random`. La respuesta es siempre 200 (exista o no el email) para prevenir enumeración de usuarios.

**Paso 2 — Enviar la solicitud de login**

```
POST /api/v1/auth/login
```

El cliente debe:

```python
import hashlib, secrets, base64, os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Valores recibidos del challenge:
salt   = "<hex del servidor>"
random = "<hex del servidor>"

# 1. Calcular hash de contraseña (lo mismo que el servidor almacena)
pw_sha256 = hashlib.sha256(password.encode()).hexdigest()

# 2. Derivar clave temporal con HKDF
ikm = (pw_sha256 + random).encode()
temp_key = HKDF(
    algorithm=hashes.SHA256(), length=32,
    salt=salt.encode(), info=b"iotmx-temp-key-v2",
).derive(ikm)

# 3. Cifrar {"random2": ...} con AES-256-GCM
random2 = secrets.token_hex(32)
nonce = os.urandom(12)           # 96-bit nonce para GCM
aesgcm = AESGCM(temp_key)
ciphertext = aesgcm.encrypt(nonce, b'{"random2":"' + random2.encode() + b'"}', None)
```

Cuerpo de la solicitud:
```json
{
  "username": "usuario@ejemplo.com",
  "payload": "<base64 del ciphertext con tag>",
  "random": "<hex del nonce del challenge>",
  "iv": "<base64 del nonce GCM de 12 bytes>"
}
```

**Paso 3 — Procesar la respuesta**

```json
{
  "payload": "<base64 del ciphertext>",
  "iv": "<base64 del nonce GCM>"
}
```

Descifre con `temp_key` y el `iv` de la respuesta. El JSON resultante contiene:
```json
{
  "random3": "<hex>",
  "session-id": "<uuid>"
}
```

La **clave de sesión** se deriva con HKDF:
```python
ikm2 = (random2 + random3).encode()
session_key = HKDF(
    algorithm=hashes.SHA256(), length=32,
    salt=None, info=b"iotmx-session-key-v2",
).derive(ikm2)
```

Guarde `session_key` y `session-id`. No los transmita en claro.

---

### Solicitudes autenticadas

Todas las solicitudes posteriores al login deben incluir:

```
X-Session-ID: <uuid de sesión>
```

El **cuerpo** se envía cifrado con AES-256-GCM usando la `session_key` (nonce de 12 bytes):

```json
{
  "payload": "<base64 del ciphertext con tag de autenticación>",
  "iv": "<base64 del nonce de 12 bytes>"
}
```

El **cuerpo de la respuesta** también llega cifrado con el mismo formato. Descífrelo con la misma `session_key`. Si el tag de autenticación no coincide, el servidor devuelve 400.

---

### Renovación de sesión

Para obtener un nuevo `session-id` con TTL renovado (sin repetir el handshake completo):

```
POST /api/v1/auth/renew
X-Session-ID: <session-id actual>
```

Respuesta (descifrada):
```json
{
  "new_session_id": "<nuevo uuid>"
}
```

El `session-id` anterior queda invalidado. Use el nuevo en todas las solicitudes siguientes.

---

### Cambio de contraseña

```
PATCH /api/v1/auth/change-password
X-Session-ID: <session-id>
```

Cuerpo (cifrado con session_key):
```json
{
  "current_password": "actual",
  "new_password": "nueva-contraseña"
}
```

---

### Cierre de sesión

```
POST /api/v1/auth/logout
X-Session-ID: <session-id>
```

El `session-id` queda invalidado de inmediato en el servidor. No se requiere cuerpo.

---

## Gestión de usuarios (administrator / master_admin)

### Crear usuario

```
POST /api/v1/users
```
Cuerpo (cifrado):
```json
{
  "first_name": "Juan",
  "last_name": "Pérez",
  "email": "juan@ejemplo.com",
  "password": "Segura123!",
  "curp": "PERJ900615HDFLRN07",
  "rfc": "PERJ900615AB1"
}
```

### Listar usuarios

```
GET /api/v1/users?offset=0&limit=20
```

### Ver perfil de usuario

```
GET /api/v1/users/{id}
```

### Actualizar usuario

```
PATCH /api/v1/users/{id}
```

### Eliminar usuario

```
DELETE /api/v1/users/{id}
```

---

## Gestión de dispositivos

### Registrar dispositivo (administrator / manager)

```
POST /api/v1/devices
```
Cuerpo (cifrado):
```json
{
  "name": "Sensor Temp-01",
  "brand": "Acme",
  "model": "T100",
  "serial_number": "SN-001",
  "ip": "192.168.1.50",
  "mac": "AA:BB:CC:DD:EE:FF"
}
```

### Listar dispositivos

```
GET /api/v1/devices
```
Los managers solo ven los dispositivos asignados a sus servicios.

### Actualizar / eliminar dispositivo

```
PATCH /api/v1/devices/{id}
DELETE /api/v1/devices/{id}   # Solo administrators
```

---

## Gestión de servicios

### Crear servicio (administrator)

```
POST /api/v1/services
```
Cuerpo (cifrado):
```json
{
  "name": "Monitoreo Industrial",
  "description": "Servicio de telemetría"
}
```

### Asignar usuario a servicio

```
POST /api/v1/payments/user-services/{user_id}/{service_id}
```

### Ver servicios de un usuario

```
GET /api/v1/payments/user-services/user/{user_id}
```

---

## Pagos y suscripciones

### Tipos de suscripción disponibles

```
GET /api/v1/payments/subscription-types
```

### Crear pago (activa el servicio)

```
POST /api/v1/payments
```
Cuerpo (cifrado):
```json
{
  "user_service_id": "uuid-del-user-service",
  "subscription_type_id": "uuid-del-tipo",
  "deposit_id": "BBVA-2026-001",
  "amount": 100.00
}
```

Al crear un pago exitoso, `UserService.is_active` pasa automáticamente a `true`. Cuando el pago vence, el servicio se desactiva automáticamente.

### Ver historial de pagos

```
GET /api/v1/payments/{payment_id}/history
```

---

## Tickets de soporte

### Ticket de servicio (usuario final)

```
POST /api/v1/tickets/service
```
Cuerpo (cifrado):
```json
{
  "title": "Error en sensor",
  "description": "El sensor T-01 no reporta",
  "user_role_id": "uuid-del-user-role",
  "service_id": "uuid-del-servicio",
  "status_id": 1,
  "priority": "high"
}
```

Prioridades: `low | medium | high | critical`

### Ticket de ecosistema (manager)

```
POST /api/v1/tickets/ecosystem
```

### Actualizar estado de ticket

```
PATCH /api/v1/tickets/service/{id}
PATCH /api/v1/tickets/ecosystem/{id}
```

---

## Roles y asignaciones

### Crear rol (master_admin)

```
POST /api/v1/roles
```
Cuerpo (cifrado):
```json
{
  "name": "operador-turno-nocturno",
  "service_id": "uuid-del-servicio"
}
```

### Asignar rol a usuario

```
POST /api/v1/users/{user_id}/roles/{role_id}
```

### Ver roles de un usuario

```
GET /api/v1/users/{user_id}/roles
```

---

## Rate limiting

La API limita a **3 peticiones por segundo** por IP en los endpoints de autenticación, tickets, managers y roles. Si supera el límite recibirá:

```
HTTP 429 Too Many Requests
Retry-After: 1
```

---

## Monitoreo de salud

```
GET /health    → {"status": "ok"}
GET /ready     → {"status": "ready"}
```

Estos endpoints no requieren autenticación y son útiles para health checks de infraestructura.

---

## Códigos de error comunes

| Código | Significado |
|--------|-------------|
| 400 | Datos inválidos en la solicitud o payload cifrado malformado |
| 401 | Sesión ausente, expirada o inválida |
| 403 | Rol sin permiso para esta acción |
| 404 | Recurso no encontrado |
| 409 | Conflicto (registro duplicado) |
| 422 | Error de validación de esquema |
| 413 | Cuerpo de la solicitud supera el límite de 1 MB |
| 429 | Demasiadas solicitudes |
| 503 | Servicio de sesiones no disponible (Valkey) |
