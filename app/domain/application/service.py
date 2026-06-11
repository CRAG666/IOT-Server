from abc import ABC
from typing import Annotated, override
from uuid import UUID
from fastapi import Depends
from app.shared.base_domain.service import IBaseService, BaseService
from app.database.model import Application
from app.database import SessionDep
from app.domain.application.repository import ApplicationRepository
from app.domain.application.schemas import ApplicationCreate, ApplicationUpdate
from app.shared.authorization.dependencies import get_current_user_from_context
from app.shared.exceptions import NotFoundException
from app.shared.pagination import PageResponse
import secrets


class IApplicationService(IBaseService[Application, ApplicationCreate, ApplicationUpdate], ABC):
    pass


class ApplicationService(BaseService[Application, ApplicationCreate, ApplicationUpdate], IApplicationService):
    entity_name = "Application"
    repository_class = ApplicationRepository
    audit_excluded_fields = BaseService.audit_excluded_fields | frozenset({"api_key"})

    @override
    def get_all(self, offset: int = 0, limit: int = 20) -> PageResponse[Application]:
        current_user = get_current_user_from_context()
        if current_user is None:
            return super().get_all(offset, limit)

        if current_user.account_type == "administrator":
            items, total = self.repository.get_all(offset, limit)
        elif current_user.account_type == "manager":
            items, total = self.repository.get_for_manager(current_user.account_id, offset, limit)
        elif current_user.account_type == "user":
            return PageResponse(total=0, offset=offset, limit=limit, data=[])
        else:
            return PageResponse(total=0, offset=offset, limit=limit, data=[])

        return PageResponse(total=total, offset=offset, limit=limit, data=items)

    @override
    def get_by_id(self, id: UUID) -> Application:
        entity = self.repository.get_by_id(id)
        if not entity:
            raise NotFoundException(self.entity_name, id)

        current_user = get_current_user_from_context()
        if current_user is None:
            return entity

        if current_user.account_type == "administrator":
            return entity

        if current_user.account_type == "manager":
            if not self.repository.check_manager_access(id, current_user.account_id):
                raise NotFoundException(self.entity_name, id)
            return entity

        raise NotFoundException(self.entity_name, id)


def get_application_service(session: SessionDep) -> ApplicationService:
    return ApplicationService(session)


ApplicationServiceDep = Annotated[ApplicationService, Depends(get_application_service)]
