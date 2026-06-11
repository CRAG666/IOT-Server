from abc import ABC
from uuid import UUID
from app.shared.base_domain.service import IBaseService
from app.database.model import Device
from typing import Annotated, override
from fastapi import Depends
from app.shared.base_domain.service import BaseService
from app.domain.device.repository import DeviceRepository
from app.database import SessionDep
from app.domain.device.schemas import DeviceCreate, DeviceUpdate
from app.shared.authorization.dependencies import get_current_user_from_context
from app.shared.exceptions import NotFoundException
from app.shared.pagination import PageResponse


class IDeviceService(IBaseService[Device, DeviceCreate, DeviceUpdate]):
    pass


class DeviceService(BaseService[Device, DeviceCreate, DeviceUpdate], IDeviceService):
    entity_name = "Device"
    repository_class = DeviceRepository
    audit_excluded_fields = BaseService.audit_excluded_fields | frozenset({"encryption_key"})

    @override
    def get_all(self, offset: int = 0, limit: int = 20) -> PageResponse[Device]:
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
    def get_by_id(self, id: UUID) -> Device:
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

        if current_user.account_type == "user":
            raise NotFoundException(self.entity_name, id)

        raise NotFoundException(self.entity_name, id)


def get_device_service(session: SessionDep) -> DeviceService:
    return DeviceService(session)


DeviceServiceDep = Annotated[DeviceService, Depends(get_device_service)]
