from abc import ABC
from typing import Annotated
from datetime import datetime, timedelta, timezone
from uuid import UUID
from fastapi import Depends, HTTPException, status
from sqlmodel import select

from app.shared.base_domain.service import IBaseService, BaseService
from app.database.model import Payment, UserService, SubscriptionType, PaymentHistory
from app.database import SessionDep
from app.domain.payment.repository import PaymentRepository
from app.domain.payment.schemas import PaymentCreate


BILLING_PERIODS = {
    "mensual": 30,
    "bimestral": 60,
    "anual": 365,
}


class IPaymentService(IBaseService[Payment, PaymentCreate, PaymentCreate], ABC):
    pass


class PaymentService(BaseService[Payment, PaymentCreate, PaymentCreate], IPaymentService):
    entity_name = "Payment"
    repository_class = PaymentRepository

    def _calculate_expires_at(self, subscription_type: SubscriptionType, current_expires: datetime | None = None) -> datetime:
        """
        Calcular fecha de vencimiento.
        Si hay un vencimiento actual vigente, extiende desde ahí.
        Si no, extiende desde ahora.
        """
        type_name = subscription_type.type.lower()
        days = BILLING_PERIODS.get(type_name)
        if not days:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Tipo de suscripción '{subscription_type.type}' no tiene periodo definido. "
                       f"Disponibles: {', '.join(BILLING_PERIODS.keys())}",
            )

        now = datetime.now(timezone.utc)

        if current_expires and current_expires > now:
            return current_expires + timedelta(days=days)

        return now + timedelta(days=days)

    def create_entity(self, payload: PaymentCreate) -> Payment:
        """
        Crear un pago + historial automático + activar acceso.

        Flujo:
        1. Validar que UserService existe
        2. Validar que SubscriptionType existe
        3. Calcular expires_at
        4. Crear Payment
        5. Crear PaymentHistory automáticamente
        6. Activar UserService.is_active = True
        """
        session = self.repository.session

        
        user_service = session.get(UserService, payload.user_service_id)
        if not user_service:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="UserService not found",
            )

        
        subscription_type = session.get(SubscriptionType, payload.subscription_type_id)
        if not subscription_type:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="SubscriptionType not found",
            )

        
        last_payment = session.exec(
            select(Payment)
            .where(Payment.user_service_id == payload.user_service_id)
            .order_by(Payment.expires_at.desc())
        ).first()

        current_expires = last_payment.expires_at if last_payment else None
        now = datetime.now(timezone.utc)
        expires_at = self._calculate_expires_at(subscription_type, current_expires)

        
        payment = Payment(
            user_service_id=payload.user_service_id,
            subscription_type_id=payload.subscription_type_id,
            expires_at=expires_at,
        )
        session.add(payment)
        session.flush()

        
        period_start = current_expires if (current_expires and current_expires > now) else now
        history = PaymentHistory(
            payment_id=payment.id,
            deposit_id=payload.deposit_id,
            amount=payload.amount,
            period_start=period_start,
            period_end=expires_at,
        )
        session.add(history)

        
        user_service.is_active = True
        session.add(user_service)

        session.commit()
        session.refresh(payment)
        return payment

    def check_and_update_expired(self, user_service_id: UUID) -> None:
        """
        Verificar si el último pago venció y desactivar UserService.
        Se llama automáticamente al consultar servicios de un usuario.
        """
        session = self.repository.session

        last_payment = session.exec(
            select(Payment)
            .where(Payment.user_service_id == user_service_id)
            .order_by(Payment.expires_at.desc())
        ).first()

        if not last_payment:
            return

        now = datetime.now(timezone.utc)
        expires = last_payment.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            user_service = session.get(UserService, user_service_id)
            if user_service and user_service.is_active:
                user_service.is_active = False
                session.add(user_service)
                session.commit()

    def check_all_user_subscriptions(self, user_id: UUID) -> None:
        """
        Verificar vencimiento de todos los servicios de un usuario.
        """
        session = self.repository.session

        user_services = session.exec(
            select(UserService).where(UserService.user_id == user_id)
        ).all()

        for us in user_services:
            self.check_and_update_expired(us.id)

    def check_all_service_subscriptions(self, service_id: UUID) -> None:
        """
        Verificar vencimiento de todos los usuarios de un servicio.
        """
        session = self.repository.session

        user_services = session.exec(
            select(UserService).where(UserService.service_id == service_id)
        ).all()

        for us in user_services:
            self.check_and_update_expired(us.id)


def get_payment_service(session: SessionDep) -> PaymentService:
    return PaymentService(session)


PaymentServiceDep = Annotated[PaymentService, Depends(get_payment_service)]
