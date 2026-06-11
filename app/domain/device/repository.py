from abc import ABC
from uuid import UUID
from sqlalchemy import text
from sqlmodel import Session, select, col
from app.shared.base_domain.repository import IBaseRepository
from app.database.model import Device
from app.shared.base_domain.repository import BaseRepository


class IDeviceRepository(IBaseRepository[Device], ABC):
    pass


class DeviceRepository(BaseRepository[Device], IDeviceRepository):
    model = Device

    def __init__(self, session: Session):
        super().__init__(session)

    def get_for_manager(self, manager_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[Device], int]:
        subq = text("SELECT device_id FROM device_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        count_q = text("SELECT COUNT(device_id) FROM device_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        total = self.session.exec(count_q).scalar_one()

        if total == 0:
            return [], 0

        stmt = (
            select(Device)
            .where(col(Device.id).in_(subq))
            .order_by(Device.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        return items, total

    def check_manager_access(self, device_id: UUID, manager_id: UUID) -> bool:
        sql = text("SELECT 1 FROM device_manager_vw WHERE device_id = :did AND manager_id = :mid").bindparams(did=device_id, mid=manager_id)
        return self.session.exec(sql).first() is not None
