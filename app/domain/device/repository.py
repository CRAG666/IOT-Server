from abc import ABC
from app.shared.base_domain.repository import IBaseRepository
from app.database.model import Device
from sqlmodel import Session
from app.shared.base_domain.repository import BaseRepository


class IDeviceRepository(IBaseRepository[Device], ABC):
    pass


class DeviceRepository(BaseRepository[Device], IDeviceRepository):
    model = Device

    def __init__(self, session: Session):
        super().__init__(session)
