from fastapi import Depends

from app.shared.base_domain.controller import FullCrudApiController
from app.domain.user.schemas import UserResponse
from app.domain.user.service import UserServiceDep
from app.domain.auth.service import require_admin, require_admin_or_manager
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate


class UserController(FullCrudApiController):
    prefix = "/users"
    tags = ["Users"]

    service_dep = UserServiceDep
    response_schema = UserResponse
    create_schema = PersonalDataCreate
    update_schema = PersonalDataUpdate

    list_dependencies = [Depends(require_admin_or_manager)]
    retrieve_dependencies = [Depends(require_admin_or_manager)]
    create_dependencies = [Depends(require_admin)]
    update_dependencies = [Depends(require_admin)]
    delete_dependencies = [Depends(require_admin)]


user_router = UserController().router