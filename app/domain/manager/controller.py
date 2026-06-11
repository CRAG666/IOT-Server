from fastapi import Depends

from app.shared.base_domain.controller import FullCrudApiController
from app.domain.manager.schemas import ManagerResponse
from app.domain.manager.service import ManagerServiceDep
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate
from app.database.model import Manager
from app.shared.rate_limit import rate_limiter


class ManagerController(FullCrudApiController):
    prefix = "/managers"
    tags = ["Managers"]
    model_class = Manager
    service_dep = ManagerServiceDep
    response_schema = ManagerResponse
    create_schema = PersonalDataCreate
    update_schema = PersonalDataUpdate

    router_dependencies = [Depends(rate_limiter(max_requests=3, window_seconds=1.0, scope="managers"))]


manager_router = ManagerController().router
