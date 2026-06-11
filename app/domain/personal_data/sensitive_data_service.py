from abc import ABC
from sqlmodel import select
from app.shared.base_domain.service import IBaseService, BaseService
from app.shared.exceptions import AlreadyExistsException
from app.database.model import SensitiveData
from app.domain.personal_data.sensitive_data_repository import SensitiveDataRepository
from app.domain.personal_data.schemas import SensitiveDataCreate, SensitiveDataUpdate


class ISensitiveDataService(
    IBaseService[SensitiveData, SensitiveDataCreate, SensitiveDataUpdate]
):
    pass


class SensitiveDataService(
    BaseService[SensitiveData, SensitiveDataCreate, SensitiveDataUpdate]
):
    entity_name = "SensitiveData"
    repository_class = SensitiveDataRepository
    audit_excluded_fields = BaseService.audit_excluded_fields | frozenset({"password_hash", "curp", "rfc"})

    def email_exists(self, email: str) -> bool:
        return bool(self.repository.session.exec(
            select(SensitiveData).where(SensitiveData.email == email)
        ).first())
