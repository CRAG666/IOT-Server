from abc import ABC
from enum import Enum
from typing import Any, ClassVar, Type
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from app.shared.pagination import PageParams, PageResponse
from app.shared.rate_limit import enforce_request_rate_limit
from app.shared.authorization.dependencies import require_read, require_write, require_delete


class BaseApiController(ABC):
    service_dep: ClassVar[Any]  # Annotated[ConcreteService, Depends(get_service)]
    response_schema: Type[BaseModel]
    create_schema: Type[BaseModel] | None = None
    update_schema: Type[BaseModel] | None = None

    prefix: str
    tags: list[str | Enum] | None = None

    # Set model_class to enable automatic CRUD→Casbin permission wiring.
    # list/retrieve → read, create/update → write, delete → delete.
    # Override individual *_dependencies to deviate from these defaults.
    model_class: ClassVar[type | None] = None

    router_dependencies: list | None = None
    list_dependencies: list | None = None
    retrieve_dependencies: list | None = None
    create_dependencies: list | None = None
    update_dependencies: list | None = None
    delete_dependencies: list | None = None

    def __init__(self):
        if self.model_class is not None:
            mc = self.model_class
            if self.list_dependencies is None:
                self.list_dependencies = [require_read(mc)]
            if self.retrieve_dependencies is None:
                self.retrieve_dependencies = [require_read(mc)]
            if self.create_dependencies is None:
                self.create_dependencies = [require_write(mc)]
            if self.update_dependencies is None:
                self.update_dependencies = [require_write(mc)]
            if self.delete_dependencies is None:
                self.delete_dependencies = [require_delete(mc)]

        self.router = APIRouter(
            prefix=self.prefix,
            tags=self.tags or [self.prefix.strip("/").title()],
            dependencies=[Depends(enforce_request_rate_limit), *(self.router_dependencies or [])],
        )
        self._register_routes()

    def _register_routes(self):
        pass  # pragma: no cover


class ReadOnlyApiController(BaseApiController):
    def _register_routes(self):
        def list(service: self.service_dep, page: PageParams = Depends()):
            return service.get_all(offset=page.offset, limit=page.limit)

        self.router.add_api_route(
            "/",
            list,
            methods=["GET"],
            response_model=PageResponse[self.response_schema],
            dependencies=self.list_dependencies,
        )

        def retrieve(service: self.service_dep, resource_id: UUID):
            return service.get_by_id(resource_id)

        self.router.add_api_route(
            "/{resource_id}",
            retrieve,
            methods=["GET"],
            response_model=self.response_schema,
            dependencies=self.retrieve_dependencies,
        )


class ImmutableApiController(ReadOnlyApiController):
    def _register_routes(self):
        super()._register_routes()

        def create(service: self.service_dep, payload: self.create_schema):
            return service.create_entity(payload)

        self.router.add_api_route(
            "/",
            create,
            methods=["POST"],
            response_model=self.response_schema,
            status_code=status.HTTP_201_CREATED,
            dependencies=self.create_dependencies,
        )


class FullCrudApiController(ImmutableApiController):
    def _register_routes(self):
        super()._register_routes()

        def update(
            service: self.service_dep, resource_id: UUID, payload: self.update_schema
        ):
            return service.update_entity(resource_id, payload)

        self.router.add_api_route(
            "/{resource_id}",
            update,
            methods=["PATCH"],
            response_model=self.response_schema,
            dependencies=self.update_dependencies,
        )

        def delete(service: self.service_dep, resource_id: UUID):
            service.delete_entity(resource_id)

        self.router.add_api_route(
            "/{resource_id}",
            delete,
            methods=["DELETE"],
            status_code=status.HTTP_204_NO_CONTENT,
            dependencies=self.delete_dependencies,
        )
