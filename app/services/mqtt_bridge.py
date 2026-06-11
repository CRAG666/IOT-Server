"""MQTT bridge — subscribes to device telemetry topics and persists to MongoDB.

Topic convention:
    iot/<device_id>/telemetry  — device publishes JSON payload here

The bridge runs as a background asyncio task started in the app lifespan.
It is disabled when settings.MQTT_ENABLED is False so the app starts cleanly
in development environments without a broker.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from app.config import settings

logger = logging.getLogger(__name__)

_TOPIC_PREFIX = "iot/"
_TOPIC_SUFFIX = "/telemetry"
_SUBSCRIBE_WILDCARD = "iot/+/telemetry"


def _parse_device_id(topic: str) -> UUID | None:
    """Extract device UUID from ``iot/<device_id>/telemetry``."""
    parts = topic.split("/")
    if len(parts) != 3:
        return None
    try:
        return UUID(parts[1])
    except ValueError:
        return None


async def run_bridge() -> None:  # pragma: no cover
    """Connect to the MQTT broker and forward device telemetry to MongoDB.

    This coroutine runs indefinitely; call it from the app lifespan.
    """
    import aiomqtt

    from app.domain.telemetry.repository import TelemetryRepository
    from app.domain.telemetry.schemas import TelemetryPoint
    from app.shared.mongodb import get_mongo_db

    repo = TelemetryRepository(get_mongo_db())

    reconnect_delay = 5  # seconds

    while True:
        try:
            client_kwargs: dict = {
                "hostname": settings.MQTT_HOST,
                "port": settings.MQTT_PORT,
            }
            if settings.MQTT_USERNAME:
                client_kwargs["username"] = settings.MQTT_USERNAME
            if settings.MQTT_PASSWORD:
                client_kwargs["password"] = settings.MQTT_PASSWORD

            async with aiomqtt.Client(**client_kwargs) as client:
                logger.info("MQTT bridge connected to %s:%d", settings.MQTT_HOST, settings.MQTT_PORT)
                reconnect_delay = 5

                await client.subscribe(_SUBSCRIBE_WILDCARD)
                async for message in client.messages:
                    topic = str(message.topic)
                    device_id = _parse_device_id(topic)
                    if device_id is None:
                        continue

                    try:
                        raw = message.payload
                        payload = json.loads(raw.decode() if isinstance(raw, (bytes, bytearray)) else raw)
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        logger.warning("MQTT bridge: bad payload on %s: %s", topic, exc)
                        continue

                    # service_id may be embedded in the payload; fall back to a nil UUID
                    service_id_raw = payload.pop("_service_id", None)
                    try:
                        service_id = UUID(service_id_raw) if service_id_raw else UUID(int=0)
                    except ValueError:
                        service_id = UUID(int=0)

                    point = TelemetryPoint(
                        device_id=device_id,
                        service_id=service_id,
                        timestamp=datetime.now(timezone.utc),
                        payload=payload,
                    )
                    await repo.insert(point)
                    logger.debug("MQTT bridge: persisted telemetry for device %s", device_id)

        except aiomqtt.MqttError as exc:
            logger.error("MQTT bridge disconnected: %s — retrying in %ds", exc, reconnect_delay)
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)
        except asyncio.CancelledError:
            logger.info("MQTT bridge shutting down")
            return
        except Exception:
            logger.exception("MQTT bridge unexpected error — retrying in %ds", reconnect_delay)
            await asyncio.sleep(reconnect_delay)
