from abc import ABC
from uuid import UUID
from sqlalchemy import text
from sqlmodel import Session, select, col

from app.database.model import EcosystemTicket, ServiceTicket
from app.shared.base_domain.repository import BaseRepository, IBaseRepository


class IServiceTicketRepository(IBaseRepository[ServiceTicket], ABC):
    pass


class ServiceTicketRepository(BaseRepository[ServiceTicket], IServiceTicketRepository):
    model = ServiceTicket

    def __init__(self, session: Session):
        super().__init__(session)

    def get_for_manager_sql(self, manager_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[ServiceTicket], int]:
        subq = text("""
            SELECT st.id FROM service_ticket st
            JOIN service_manager_vw smv ON st.service_id = smv.service_id
            WHERE smv.manager_id = :mid
        """).bindparams(mid=manager_id)
        count_q = text("""
            SELECT COUNT(st.id) FROM service_ticket st
            JOIN service_manager_vw smv ON st.service_id = smv.service_id
            WHERE smv.manager_id = :mid
        """).bindparams(mid=manager_id)
        total = self.session.exec(count_q).scalar_one()
        if total == 0:
            return [], 0
        stmt = (
            select(ServiceTicket)
            .where(col(ServiceTicket.id).in_(subq))
            .order_by(ServiceTicket.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        return items, total

    def get_for_user(self, user_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[ServiceTicket], int]:
        stmt = (
            select(ServiceTicket)
            .where(ServiceTicket.user_role.has(user_id=user_id))
            .order_by(ServiceTicket.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        count_stmt = select(ServiceTicket).where(ServiceTicket.user_role.has(user_id=user_id))
        total = len(list(self.session.exec(count_stmt).all()))
        return items, total


class IEcosystemTicketRepository(IBaseRepository[EcosystemTicket], ABC):
    pass


class EcosystemTicketRepository(BaseRepository[EcosystemTicket], IEcosystemTicketRepository):
    model = EcosystemTicket

    def __init__(self, session: Session):
        super().__init__(session)

    def get_for_manager(self, manager_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[EcosystemTicket], int]:
        subq = text("SELECT ticket_id FROM ticket_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        count_q = text("SELECT COUNT(ticket_id) FROM ticket_manager_vw WHERE manager_id = :mid").bindparams(mid=manager_id)
        total = self.session.exec(count_q).scalar_one()
        if total == 0:
            return [], 0
        stmt = (
            select(EcosystemTicket)
            .where(col(EcosystemTicket.id).in_(subq))
            .order_by(EcosystemTicket.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = list(self.session.exec(stmt).all())
        return items, total
