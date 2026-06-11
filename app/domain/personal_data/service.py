from typing import Generic, TypeVar, override
from uuid import UUID

from sqlmodel import Session

from app.database.model import PersonalData
from app.domain.personal_data.non_critical_personal_data_service import (
    NonCriticalPersonalDataService,
)
from app.domain.personal_data.sensitive_data_service import SensitiveDataService
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate
from app.shared.base_domain.service import BaseService
from app.shared.exceptions import AlreadyExistsException

T = TypeVar("T", bound=PersonalData)


class PersonalDataService(
    BaseService[T, PersonalDataCreate, PersonalDataUpdate], Generic[T]
):
    def __init__(self, session: Session):
        super().__init__(session)
        self.non_critical_personal_data_service = NonCriticalPersonalDataService(
            session
        )
        self.sensitive_data_service = SensitiveDataService(session)

    @override
    def create_entity(self, payload: PersonalDataCreate) -> T:
        if self.sensitive_data_service.email_exists(payload.email):
            raise AlreadyExistsException("Account", "email", payload.email)
        non_critical_personal_data = (
            self.non_critical_personal_data_service.create_entity(payload)
        )
        payload.non_critical_data_id = non_critical_personal_data.id

        sensitive_data = self.sensitive_data_service.create_entity(payload)
        payload.sensitive_data_id = sensitive_data.id

        return super().create_entity(payload)

    @override
    def update_entity(self, id: UUID, payload: PersonalDataUpdate) -> T:
        entity = self.get_by_id(id)

        self.non_critical_personal_data_service.update_entity(
            entity.sensitive_data.non_critical_data_id, payload
        )
        self.sensitive_data_service.update_entity(entity.sensitive_data_id, payload)

        return super().update_entity(id, payload)

    @override
    def delete_entity(self, id: UUID) -> None:
        entity = self.get_by_id(id)

        sensitive_data_id = entity.sensitive_data_id
        non_critical_data_id = entity.sensitive_data.non_critical_data_id

        deleted = super().delete_entity(id)
        self.sensitive_data_service.delete_entity(sensitive_data_id)
        self.non_critical_personal_data_service.delete_entity(non_critical_data_id)

        return deleted
