from dataclasses import dataclass
from uuid import UUID


@dataclass
class CurrentUser:
    account_id: UUID
    account_type: str
    email: str
    is_master: bool
    sensitive_data_id: UUID
    
    @classmethod
    def from_state_dict(cls, state_dict: dict) -> "CurrentUser":
        return cls(
            account_id=UUID(state_dict["account_id"]),
            account_type=state_dict["account_type"],
            email=state_dict["email"],
            is_master=state_dict.get("is_master", False),
            sensitive_data_id=UUID(state_dict["sensitive_data_id"]),
        )
