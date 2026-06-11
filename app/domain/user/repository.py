from abc import ABC
from uuid import UUID
from sqlalchemy import text
from sqlmodel import Session, select, col
from app.shared.base_domain.repository import IBaseRepository, BaseRepository
from app.database.model import User


class IUserRepository(IBaseRepository[User], ABC):
    pass


class UserRepository(BaseRepository[User], IUserRepository):
    model = User

    def __init__(self, session: Session):
        super().__init__(session)

    def get_for_manager(self, manager_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[User], int]:
        subq = text("SELECT user_id FROM user_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        count_q = text("SELECT COUNT(user_id) FROM user_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        total = self.session.exec(count_q).scalar_one()

        if total == 0:
            return [], 0

        stmt = (
            select(User)
            .where(col(User.id).in_(subq))
            .order_by(User.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        return items, total

    def check_manager_access(self, user_id: UUID, manager_id: UUID) -> bool:
        sql = text("SELECT 1 FROM user_manager_vw WHERE user_id = :uid AND manager_id = :mid").bindparams(uid=user_id, mid=manager_id)
        return self.session.exec(sql).first() is not None
