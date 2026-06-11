
from abc import ABC
from uuid import UUID
from sqlalchemy import text
from sqlmodel import Session, select, col
from app.shared.base_domain.repository import IBaseRepository, BaseRepository
from app.database.model import Service


class IServiceRepository(IBaseRepository[Service], ABC):
    pass


class ServiceRepository(BaseRepository[Service], IServiceRepository):
    model = Service

    def __init__(self, session: Session):
        super().__init__(session)

    def get_for_manager(self, manager_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[Service], int]:
        subq = text("SELECT service_id FROM service_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        count_q = text("SELECT COUNT(service_id) FROM service_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        total = self.session.exec(count_q).scalar_one()
        if total == 0:
            return [], 0
        stmt = (
            select(Service)
            .where(col(Service.id).in_(subq))
            .order_by(Service.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        return items, total

    def check_manager_access(self, service_id: UUID, manager_id: UUID) -> bool:
        sql = text("SELECT 1 FROM service_manager_vw WHERE service_id = :sid AND manager_id = :mid").bindparams(sid=service_id, mid=manager_id)
        return self.session.exec(sql).first() is not None
