from fastapi import Depends

from app.database.model import EcosystemTicket, ServiceTicket
from app.domain.tickets.schemas import (
    EcosystemTicketCreate,
    EcosystemTicketResponse,
    EcosystemTicketUpdate,
    ServiceTicketCreate,
    ServiceTicketResponse,
    ServiceTicketUpdate,
)
from app.domain.tickets.service import EcosystemTicketServiceDep, ServiceTicketServiceDep
from app.shared.base_domain.controller import FullCrudApiController
from app.shared.rate_limit import rate_limiter


class ServiceTicketController(FullCrudApiController):
    prefix = "/tickets/service"
    tags = ["Tickets"]
    model_class = ServiceTicket
    service_dep = ServiceTicketServiceDep
    response_schema = ServiceTicketResponse
    create_schema = ServiceTicketCreate
    update_schema = ServiceTicketUpdate

    router_dependencies = [Depends(rate_limiter(max_requests=3, window_seconds=1.0, scope="tickets_service"))]


class EcosystemTicketController(FullCrudApiController):
    prefix = "/tickets/ecosystem"
    tags = ["Tickets"]
    model_class = EcosystemTicket
    service_dep = EcosystemTicketServiceDep
    response_schema = EcosystemTicketResponse
    create_schema = EcosystemTicketCreate
    update_schema = EcosystemTicketUpdate

    router_dependencies = [Depends(rate_limiter(max_requests=3, window_seconds=1.0, scope="tickets_ecosystem"))]


service_ticket_router = ServiceTicketController().router
ecosystem_ticket_router = EcosystemTicketController().router
