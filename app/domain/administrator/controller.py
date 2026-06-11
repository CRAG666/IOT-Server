from app.shared.base_domain.controller import FullCrudApiController
from app.domain.administrator.schemas import AdministratorResponse
from app.domain.administrator.service import AdministratorServiceDep
from app.shared.authorization.dependencies import require_administer
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate
from app.database.model import Administrator


class AdministratorController(FullCrudApiController):
    prefix = "/administrators"
    tags = ["Administrators"]

    model_class = Administrator
    service_dep = AdministratorServiceDep
    response_schema = AdministratorResponse
    create_schema = PersonalDataCreate
    update_schema = PersonalDataUpdate

    # list/retrieve default to require_read(Administrator) via model_class
    create_dependencies = [require_administer(Administrator)]
    update_dependencies = [require_administer(Administrator)]
    delete_dependencies = [require_administer(Administrator)]


administrator_router = AdministratorController().router