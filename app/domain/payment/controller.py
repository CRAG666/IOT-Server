from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy import delete as _sa_delete
from sqlmodel import select

from app.shared.base_domain.controller import FullCrudApiController
from app.domain.payment.schemas import (
    PaymentCreate,
    PaymentResponse,
    PaymentHistoryResponse,
    SubscriptionTypeCreate,
    SubscriptionTypeUpdate,
    SubscriptionTypeResponse,
    UserServiceResponse,
)
from app.domain.payment.service import PaymentServiceDep
from app.database import SessionDep
from app.database.model import (
    Payment,
    PaymentHistory,
    SubscriptionType,
    UserService,
    User,
    Service,
)
class PaymentController(FullCrudApiController):
    prefix = "/payments"
    tags = ["Payments"]
    model_class = Payment
    service_dep = PaymentServiceDep
    response_schema = PaymentResponse
    create_schema = PaymentCreate
    update_schema = PaymentCreate


payment_router = PaymentController().router






@payment_router.get(
    "/{payment_id}/history",
    response_model=list[PaymentHistoryResponse],
    tags=["Payment History"],
)
def list_payment_history(payment_id: UUID, session: SessionDep):
    """Listar historial de depósitos de un pago."""
    payment = session.get(Payment, payment_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    results = session.exec(
        select(PaymentHistory).where(PaymentHistory.payment_id == payment_id)
    ).all()
    return results




@payment_router.post(
    "/subscription-types",
    response_model=SubscriptionTypeResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Subscription Types"],
)
def create_subscription_type(payload: SubscriptionTypeCreate, session: SessionDep):
    """Crear un tipo de suscripción."""
    existing = session.exec(
        select(SubscriptionType).where(SubscriptionType.type == payload.type)
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Subscription type already exists")

    sub_type = SubscriptionType(type=payload.type, cost=payload.cost)
    session.add(sub_type)
    session.commit()
    session.refresh(sub_type)
    return sub_type


@payment_router.get(
    "/subscription-types",
    response_model=list[SubscriptionTypeResponse],
    tags=["Subscription Types"],
)
def list_subscription_types(session: SessionDep):
    """Listar todos los tipos de suscripción."""
    return session.exec(select(SubscriptionType)).all()


@payment_router.get(
    "/subscription-types/{type_id}",
    response_model=SubscriptionTypeResponse,
    tags=["Subscription Types"],
)
def get_subscription_type(type_id: UUID, session: SessionDep):
    """Obtener un tipo de suscripción por ID."""
    sub_type = session.get(SubscriptionType, type_id)
    if not sub_type:
        raise HTTPException(status_code=404, detail="Subscription type not found")
    return sub_type


@payment_router.patch(
    "/subscription-types/{type_id}",
    response_model=SubscriptionTypeResponse,
    tags=["Subscription Types"],
)
def update_subscription_type(type_id: UUID, payload: SubscriptionTypeUpdate, session: SessionDep):
    """Actualizar un tipo de suscripción."""
    sub_type = session.get(SubscriptionType, type_id)
    if not sub_type:
        raise HTTPException(status_code=404, detail="Subscription type not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(sub_type, key, value)

    session.add(sub_type)
    session.commit()
    session.refresh(sub_type)
    return sub_type


@payment_router.delete(
    "/subscription-types/{type_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Subscription Types"],
)
def delete_subscription_type(type_id: UUID, session: SessionDep):
    """Eliminar un tipo de suscripción."""
    sub_type = session.get(SubscriptionType, type_id)
    if not sub_type:
        raise HTTPException(status_code=404, detail="Subscription type not found")

    session.execute(_sa_delete(SubscriptionType).where(SubscriptionType.id == type_id))
    session.commit()




@payment_router.post(
    "/user-services/{user_id}/{service_id}",
    response_model=UserServiceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["User Services"],
)
def assign_user_to_service(user_id: UUID, service_id: UUID, session: SessionDep):
    """Asignar usuario a servicio (is_active=false hasta que pague)."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    service = session.get(Service, service_id)
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    existing = session.exec(
        select(UserService).where(
            UserService.user_id == user_id,
            UserService.service_id == service_id,
        )
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already assigned to this service")

    user_service = UserService(user_id=user_id, service_id=service_id, is_active=False)
    session.add(user_service)
    session.commit()
    session.refresh(user_service)
    return user_service


@payment_router.delete(
    "/user-services/{user_id}/{service_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["User Services"],
)
def unassign_user_from_service(user_id: UUID, service_id: UUID, session: SessionDep):
    """Desasignar usuario de servicio."""
    user_service = session.exec(
        select(UserService).where(
            UserService.user_id == user_id,
            UserService.service_id == service_id,
        )
    ).first()
    if not user_service:
        raise HTTPException(status_code=404, detail="User not assigned to this service")

    session.execute(_sa_delete(UserService).where(
        UserService.user_id == user_id,
        UserService.service_id == service_id,
    ))
    session.commit()


@payment_router.get(
    "/user-services/user/{user_id}",
    response_model=list[UserServiceResponse],
    tags=["User Services"],
)
def list_user_services(user_id: UUID, session: SessionDep, service: PaymentServiceDep):
    """Listar servicios de un usuario. Verifica vencimientos automáticamente."""
    service.check_all_user_subscriptions(user_id)
    results = session.exec(
        select(UserService).where(UserService.user_id == user_id)
    ).all()
    return results


@payment_router.get(
    "/user-services/service/{service_id}",
    response_model=list[UserServiceResponse],
    tags=["User Services"],
)
def list_service_users(service_id: UUID, session: SessionDep, service: PaymentServiceDep):
    """Listar usuarios de un servicio. Verifica vencimientos automáticamente."""
    service.check_all_service_subscriptions(service_id)
    results = session.exec(
        select(UserService).where(UserService.service_id == service_id)
    ).all()
    return results


specific_routes = [r for r in payment_router.routes if hasattr(r, 'path') and '{' not in r.path]
generic_routes = [r for r in payment_router.routes if not hasattr(r, 'path') or '{' in r.path]
payment_router.routes = specific_routes + generic_routes
