from abc import ABC
from typing import Annotated, override
from uuid import UUID
from fastapi import Depends

from fastapi import HTTPException, status
from sqlmodel import select

from app.shared.base_domain.service import IBaseService
from app.database.model import Role, User, UserRole
from app.database import SessionDep
from app.domain.user.repository import UserRepository
from app.domain.personal_data.schemas import PersonalDataCreate, PersonalDataUpdate
from app.domain.personal_data.service import PersonalDataService
from app.shared.authorization.dependencies import get_current_user_from_context
from app.shared.exceptions import NotFoundException
from app.shared.pagination import PageResponse


class IUserService(IBaseService[User, PersonalDataCreate, PersonalDataUpdate], ABC):
    pass


class UserService(PersonalDataService[User], IUserService):
    entity_name = "User"
    repository_class = UserRepository

    @override
    def get_all(self, offset: int = 0, limit: int = 20) -> PageResponse[User]:
        current_user = get_current_user_from_context()
        if current_user is None:
            return super().get_all(offset, limit)

        if current_user.account_type == "administrator":
            items, total = self.repository.get_all(offset, limit)
        elif current_user.account_type == "manager":
            items, total = self.repository.get_for_manager(
                current_user.account_id, offset, limit
            )
        elif current_user.account_type == "user":
            entity = self.repository.get_by_id(current_user.account_id)
            items = [entity] if entity else []
            total = 1 if entity else 0
        else:
            return PageResponse(total=0, offset=offset, limit=limit, data=[])

        return PageResponse(total=total, offset=offset, limit=limit, data=items)

    @override
    def get_by_id(self, id: UUID) -> User:
        entity = self.repository.get_by_id(id)
        if not entity:
            raise NotFoundException(self.entity_name, id)

        current_user = get_current_user_from_context()
        if current_user is None:
            return entity

        if current_user.account_type == "administrator":
            return entity

        if current_user.account_type == "manager":
            if not self.repository.check_manager_access(id, current_user.account_id):
                raise NotFoundException(self.entity_name, id)
            return entity

        if current_user.account_type == "user":
            if entity.id != current_user.account_id:
                raise NotFoundException(self.entity_name, id)
            return entity

        raise NotFoundException(self.entity_name, id)

    def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> UserRole:
        user = self.repository.get_by_id(user_id)
        if not user:
            raise NotFoundException("User", user_id)
        role = self.repository.session.get(Role, role_id)
        if not role:
            raise NotFoundException("Role", role_id)
        existing = self.repository.session.exec(
            select(UserRole).where(
                UserRole.user_id == user_id, UserRole.role_id == role_id
            )
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Role already assigned to user",
            )
        user_role = UserRole(user_id=user_id, role_id=role_id)
        self.repository.session.add(user_role)
        self.repository.session.commit()
        self.repository.session.refresh(user_role)
        return user_role

    def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> None:
        user_role = self.repository.session.exec(
            select(UserRole).where(
                UserRole.user_id == user_id, UserRole.role_id == role_id
            )
        ).first()
        if not user_role:
            raise NotFoundException("UserRole", role_id)
        self.repository.session.delete(user_role)
        self.repository.session.commit()

    def list_roles_by_user(self, user_id: UUID) -> list[Role]:
        user = self.repository.get_by_id(user_id)
        if not user:
            raise NotFoundException("User", user_id)
        user_roles = self.repository.session.exec(
            select(UserRole).where(UserRole.user_id == user_id)
        ).all()
        return [ur.role for ur in user_roles]


def get_user_service(session: SessionDep) -> UserService:
    return UserService(session)


UserServiceDep = Annotated[UserService, Depends(get_user_service)]
