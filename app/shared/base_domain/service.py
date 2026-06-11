from typing import ClassVar, Generic, TypeVar
from uuid import UUID
import json
from pydantic import BaseModel
from sqlmodel import Session
from app.shared.base_domain.model import BaseTable
from app.shared.base_domain.repository import IBaseRepository, BaseRepository
from app.shared.exceptions import NotFoundException
from app.shared.pagination import PageResponse
from app.shared.authorization.dependencies import get_current_user_from_context
from app.domain.audit.repository import AuditRepository
from abc import ABC, abstractmethod
from loguru import logger

T = TypeVar("T", bound=BaseTable)
P_create = TypeVar("P_create", bound=BaseModel)
P_update = TypeVar("P_update", bound=BaseModel)

class IBaseService(ABC, Generic[T, P_create, P_update]):
    entity_name: str

    @abstractmethod
    def get_by_id(self, id: UUID) -> T: ...

    @abstractmethod
    def get_all(self, offset: int = 0, limit: int = 20) -> PageResponse[T]: ...

    @abstractmethod
    def create_entity(self, payload: P_create) -> T: ...

    @abstractmethod
    def update_entity(self, id: UUID, payload: P_update) -> T: ...

    @abstractmethod
    def delete_entity(self, id: UUID) -> None: ...


class BaseService(IBaseService[T, P_create, P_update], Generic[T, P_create, P_update]):
    entity_name: str = "Entidad"
    repository_class: ClassVar[type[BaseRepository]]
    audit_excluded_fields: ClassVar[frozenset[str]] = frozenset({"id", "created_at", "updated_at"})

    def __init__(self, session: Session):
        self.repository: IBaseRepository[T] = self.repository_class(session)
        self.audit = AuditRepository(session)

    def get_by_id(self, id: UUID) -> T:
        entity = self.repository.get_by_id(id)
        if not entity:
            raise NotFoundException(self.entity_name, id)
        return entity

    def get_all(self, offset: int = 0, limit: int = 20) -> PageResponse[T]:
        items, total = self.repository.get_all(offset, limit)
        return PageResponse(total=total, offset=offset, limit=limit, data=items)

    def create_entity(self, payload: P_create) -> T:
        entity = self.repository.create(self._build_entity(payload))
        self._log_audit("create", entity)
        return entity

    def update_entity(self, id: UUID, payload: P_update) -> T:
        entity = self.get_by_id(id)
        old = entity.model_dump()
        entity.sqlmodel_update(payload.model_dump(exclude_unset=True))
        updated = self.repository.update(entity)
        self._log_audit("update", entity, old)
        return updated

    def delete_entity(self, id: UUID) -> None:
        entity = self.get_by_id(id)
        self.repository.delete(entity)
        self._log_audit("delete", entity)

    def _build_entity(self, payload: P_create) -> T:
        return self.repository.model(**payload.model_dump(exclude_none=True))

    def _log_audit(self, action: str, entity: T, old: dict | None = None) -> None:
        current_user = get_current_user_from_context()
        if current_user is None:
            return

        details = None
        if action == "update" and old:
            changes = {}
            new = entity.model_dump()
            for key in [k for k in old if k not in self.audit_excluded_fields]:
                if old.get(key) != new.get(key):
                    changes[key] = {"from": str(old[key]), "to": str(new[key])}
            if changes:
                details = json.dumps(changes)

        entry = self.audit.log(
            account_id=current_user.account_id,
            account_type=current_user.account_type,
            action=action,
            resource_type=self.entity_name,
            resource_id=entity.id,
            details=details,
        )
        logger.info(
            "Audit: {action} {resource} #{id} by {user}",
            action=entry.action,
            resource=entry.resource_type,
            id=entry.resource_id,
            user=current_user.email,
        )
