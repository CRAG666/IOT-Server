from fastapi import Depends

from app.shared.base_domain.controller import FullCrudApiController
from app.domain.administrator.schemas import AdministratorResponse
from app.domain.administrator.service import AdministratorServiceDep
from app.domain.auth.service import require_master_admin
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate


class AdministratorController(FullCrudApiController):
    prefix = "/administrators"
    tags = ["Administrators"]

    service_dep = AdministratorServiceDep
    response_schema = AdministratorResponse
    create_schema = PersonalDataCreate
    update_schema = PersonalDataUpdate

    list_dependencies = [Depends(require_master_admin)]
    retrieve_dependencies = [Depends(require_master_admin)]
    create_dependencies = [Depends(require_master_admin)]
    update_dependencies = [Depends(require_master_admin)]
    delete_dependencies = [Depends(require_master_admin)]


administrator_router = AdministratorController().router