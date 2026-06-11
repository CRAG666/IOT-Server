from uuid import UUID

from fastapi import Depends, status

from app.database.model import Role, UserRole
from app.domain.role.schemas import RoleCreate, RoleResponse, RoleUpdate, UserRoleCreate, UserRoleResponse
from app.domain.role.service import RoleServiceDep
from app.shared.authorization.dependencies import require_delete, require_read, require_write
from app.shared.base_domain.controller import FullCrudApiController
from app.shared.rate_limit import rate_limiter


class RoleController(FullCrudApiController):
    prefix = "/roles"
    tags = ["Roles"]
    model_class = Role
    service_dep = RoleServiceDep
    response_schema = RoleResponse
    create_schema = RoleCreate
    update_schema = RoleUpdate

    router_dependencies = [Depends(rate_limiter(max_requests=3, window_seconds=1.0, scope="roles"))]

    def _register_routes(self):
        super()._register_routes()

        # GET /roles/{role_id}/users — listar usuarios asignados
        def get_users(
            role_id: UUID,
            service: self.service_dep,
            _auth=require_read(UserRole),
        ):
            return service.get_users_by_role(role_id)

        self.router.add_api_route(
            "/{role_id}/users",
            get_users,
            methods=["GET"],
            response_model=list[UserRoleResponse],
            dependencies=[require_read(UserRole)],
        )

        # POST /roles/{role_id}/users — asignar usuario a rol
        def assign_user(
            role_id: UUID,
            payload: UserRoleCreate,
            service: self.service_dep,
        ):
            return service.assign_user(role_id, payload.user_id)

        self.router.add_api_route(
            "/{role_id}/users",
            assign_user,
            methods=["POST"],
            response_model=UserRoleResponse,
            status_code=status.HTTP_201_CREATED,
            dependencies=[require_write(UserRole)],
        )

        # DELETE /roles/{role_id}/users/{user_id} — quitar usuario de rol
        def remove_user(
            role_id: UUID,
            user_id: UUID,
            service: self.service_dep,
        ):
            service.remove_user(role_id, user_id)

        self.router.add_api_route(
            "/{role_id}/users/{user_id}",
            remove_user,
            methods=["DELETE"],
            status_code=status.HTTP_204_NO_CONTENT,
            dependencies=[require_delete(UserRole)],
        )


role_router = RoleController().router
