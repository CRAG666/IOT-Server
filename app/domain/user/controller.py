from uuid import UUID

from fastapi import status

from app.shared.base_domain.controller import FullCrudApiController
from app.domain.role.schemas import RoleResponse
from app.domain.user.schemas import UserResponse, UserRoleResponse
from app.domain.user.service import UserServiceDep
from app.shared.authorization.dependencies import require_read, require_write
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate
from app.database.model import User


class UserController(FullCrudApiController):
    prefix = "/users"
    tags = ["Users"]

    model_class = User
    service_dep = UserServiceDep
    response_schema = UserResponse
    create_schema = PersonalDataCreate
    update_schema = PersonalDataUpdate


user_router = UserController().router


@user_router.post(
    "/{user_id}/roles/{role_id}",
    response_model=UserRoleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[require_write(User)],
)
def assign_role_to_user(
    user_id: UUID,
    role_id: UUID,
    service: UserServiceDep,
):
    return service.assign_role_to_user(
        user_id=user_id,
        role_id=role_id,
    )


@user_router.delete(
    "/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[require_write(User)],
)
def remove_role_from_user(
    user_id: UUID,
    role_id: UUID,
    service: UserServiceDep,
):
    service.remove_role_from_user(
        user_id=user_id,
        role_id=role_id,
    )


@user_router.get(
    "/{user_id}/roles",
    response_model=list[RoleResponse],
    dependencies=[require_read(User)],
)
def list_roles_by_user(
    user_id: UUID,
    service: UserServiceDep,
):
    return service.list_roles_by_user(user_id=user_id)