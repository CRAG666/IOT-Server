from typing import Literal

from pydantic import BaseModel


class AuthPathNode(BaseModel):
    position: Literal["left", "right"]
    value: str
