from typing import Generic, TypeVar
from uuid import UUID
from sqlalchemy import delete as _sa_delete
from sqlmodel import Session, select, func
from app.shared.base_domain.model import BaseTable
from abc import ABC, abstractmethod

T = TypeVar("T", bound=BaseTable)


class IBaseRepository(ABC, Generic[T]):
    @abstractmethod
    def get_by_id(self, id: UUID) -> T | None:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def get_all(self, offset: int = 0, limit: int = 20) -> tuple[list[T], int]:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def create(self, entity: T) -> T:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def update(self, entity: T) -> T:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def delete(self, entity: T) -> None:
        raise NotImplementedError  # pragma: no cover


class BaseRepository(IBaseRepository[T], Generic[T]):
    model: type[T]

    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, id: UUID) -> T | None:
        return self.session.get(self.model, id)

    def get_all(self, offset: int = 0, limit: int = 20) -> tuple[list[T], int]:
        total = self.session.exec(select(func.count()).select_from(self.model)).one()
        items = self.session.exec(select(self.model).offset(offset).limit(limit)).all()
        return list(items), total

    def create(self, entity: T) -> T:
        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)
        return entity

    def update(self, entity: T) -> T:
        entity.touch()
        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)
        return entity

    def delete(self, entity: T) -> None:
        # Use raw SQL to avoid ORM cascade nullification of NOT NULL FK columns.
        self.session.execute(_sa_delete(type(entity)).where(type(entity).id == entity.id))
        self.session.commit()
