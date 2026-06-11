from abc import ABC
from uuid import UUID
from sqlalchemy import text
from sqlmodel import Session, select, col
from app.shared.base_domain.repository import IBaseRepository, BaseRepository
from app.database.model import Application


class IApplicationRepository(IBaseRepository[Application], ABC):
    pass


class ApplicationRepository(BaseRepository[Application], IApplicationRepository):
    model = Application

    def __init__(self, session: Session):
        super().__init__(session)

    def get_for_manager(self, manager_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[Application], int]:
        subq = text("SELECT application_id FROM application_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        count_q = text("SELECT COUNT(application_id) FROM application_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        total = self.session.exec(count_q).scalar_one()
        if total == 0:
            return [], 0
        stmt = (
            select(Application)
            .where(col(Application.id).in_(subq))
            .order_by(Application.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        return items, total

    def check_manager_access(self, application_id: UUID, manager_id: UUID) -> bool:
        sql = text("SELECT 1 FROM application_manager_vw WHERE application_id = :aid AND manager_id = :mid").bindparams(aid=application_id, mid=manager_id)
        return self.session.exec(sql).first() is not None