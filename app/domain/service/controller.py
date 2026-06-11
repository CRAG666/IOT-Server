from uuid import UUID
from fastapi import HTTPException, status
from sqlmodel import select

from app.shared.base_domain.controller import FullCrudApiController
from app.domain.service.schemas import (
    ServiceCreate,
    ServiceResponse,
    ServiceUpdate,
    ManagerServiceResponse,
    ApplicationServiceResponse,
    DeviceServiceResponse,
)
from app.domain.service.service import ServiceServiceDep
from app.database import SessionDep
from app.database.model import (
    Service,
    Manager,
    Application,
    Device,
    ManagerService,
    ApplicationService,
    DeviceService,
)
class ServiceController(FullCrudApiController):
    prefix = "/services"
    tags = ["Services"]
    model_class = Service
    service_dep = ServiceServiceDep
    response_schema = ServiceResponse
    create_schema = ServiceCreate
    update_schema = ServiceUpdate


service_router = ServiceController().router


# ── Managers de un Service ──────────────────────────────────────────

@service_router.post(
    "/{service_id}/managers/{manager_id}",
    response_model=ManagerServiceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Service Managers"],
)
def assign_manager(service_id: UUID, manager_id: UUID, session: SessionDep):
    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    manager = session.get(Manager, manager_id)
    if not manager:
        raise HTTPException(status_code=404, detail="Manager not found")

    existing = session.exec(
        select(ManagerService).where(
            ManagerService.manager_id == manager_id,
            ManagerService.service_id == service_id,
        )
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Manager already assigned to this service")

    manager_service = ManagerService(manager_id=manager_id, service_id=service_id)
    session.add(manager_service)
    session.commit()
    session.refresh(manager_service)
    return manager_service


@service_router.delete(
    "/{service_id}/managers/{manager_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Service Managers"],
)
def unassign_manager(service_id: UUID, manager_id: UUID, session: SessionDep):
    manager_service = session.exec(
        select(ManagerService).where(
            ManagerService.manager_id == manager_id,
            ManagerService.service_id == service_id,
        )
    ).first()
    if not manager_service:
        raise HTTPException(status_code=404, detail="Manager not assigned to this service")

    session.delete(manager_service)
    session.commit()


@service_router.get(
    "/{service_id}/managers",
    response_model=list[ManagerServiceResponse],
    tags=["Service Managers"],
)
def list_managers(service_id: UUID, session: SessionDep):
    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    results = session.exec(
        select(ManagerService).where(ManagerService.service_id == service_id)
    ).all()
    return results


# ── Applications de un Service ──────────────────────────────────────

@service_router.post(
    "/{service_id}/applications/{application_id}",
    response_model=ApplicationServiceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Service Applications"],
)
def assign_application(service_id: UUID, application_id: UUID, session: SessionDep):
    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    application = session.get(Application, application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    existing = session.exec(
        select(ApplicationService).where(
            ApplicationService.application_id == application_id,
            ApplicationService.service_id == service_id,
        )
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Application already assigned to this service")

    app_service = ApplicationService(application_id=application_id, service_id=service_id)
    session.add(app_service)
    session.commit()
    session.refresh(app_service)
    return app_service


@service_router.delete(
    "/{service_id}/applications/{application_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Service Applications"],
)
def unassign_application(service_id: UUID, application_id: UUID, session: SessionDep):
    app_service = session.exec(
        select(ApplicationService).where(
            ApplicationService.application_id == application_id,
            ApplicationService.service_id == service_id,
        )
    ).first()
    if not app_service:
        raise HTTPException(status_code=404, detail="Application not assigned to this service")

    session.delete(app_service)
    session.commit()


@service_router.get(
    "/{service_id}/applications",
    response_model=list[ApplicationServiceResponse],
    tags=["Service Applications"],
)
def list_applications(service_id: UUID, session: SessionDep):
    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    results = session.exec(
        select(ApplicationService).where(ApplicationService.service_id == service_id)
    ).all()
    return results


# ── Devices de un Service ───────────────────────────────────────────

@service_router.post(
    "/{service_id}/devices/{device_id}",
    response_model=DeviceServiceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Service Devices"],
)
def assign_device(service_id: UUID, device_id: UUID, session: SessionDep):
    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    existing = session.exec(
        select(DeviceService).where(
            DeviceService.device_id == device_id,
            DeviceService.service_id == service_id,
        )
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Device already assigned to this service")

    device_service = DeviceService(device_id=device_id, service_id=service_id)
    session.add(device_service)
    session.commit()
    session.refresh(device_service)
    return device_service


@service_router.delete(
    "/{service_id}/devices/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Service Devices"],
)
def unassign_device(service_id: UUID, device_id: UUID, session: SessionDep):
    device_service = session.exec(
        select(DeviceService).where(
            DeviceService.device_id == device_id,
            DeviceService.service_id == service_id,
        )
    ).first()
    if not device_service:
        raise HTTPException(status_code=404, detail="Device not assigned to this service")

    session.delete(device_service)
    session.commit()


@service_router.get(
    "/{service_id}/devices",
    response_model=list[DeviceServiceResponse],
    tags=["Service Devices"],
)
def list_devices(service_id: UUID, session: SessionDep):
    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    results = session.exec(
        select(DeviceService).where(DeviceService.service_id == service_id)
    ).all()
    return results
