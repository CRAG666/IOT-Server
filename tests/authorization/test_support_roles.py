"""Tests for W6 support roles in Casbin policy."""
import pytest
from app.shared.authorization.enforcer import is_allowed


class TestSupportAgentRole:
    """support_agent: read users/services/devices, read+write service tickets."""

    def _allow(self, action: str, resource: str) -> bool:
        from app.shared.authorization.enforcer import get_enforcer
        return get_enforcer().enforce("support_agent", resource, action)

    def test_can_read_user(self):
        assert self._allow("read", "User")

    def test_can_read_service(self):
        assert self._allow("read", "Service")

    def test_can_read_device(self):
        assert self._allow("read", "Device")

    def test_can_read_service_ticket(self):
        assert self._allow("read", "ServiceTicket")

    def test_can_write_service_ticket(self):
        assert self._allow("write", "ServiceTicket")

    def test_can_read_ecosystem_ticket(self):
        assert self._allow("read", "EcosystemTicket")

    def test_cannot_delete_service_ticket(self):
        assert not self._allow("delete", "ServiceTicket")

    def test_cannot_write_ecosystem_ticket(self):
        assert not self._allow("write", "EcosystemTicket")

    def test_cannot_access_role(self):
        assert not self._allow("read", "Role")

    def test_cannot_access_administrator(self):
        assert not self._allow("read", "Administrator")

    def test_cannot_write_user(self):
        assert not self._allow("write", "User")

    def test_cannot_delete_user(self):
        assert not self._allow("delete", "User")


class TestSupportAdminRole:
    """support_admin: full ticket CRUD + read users/services/devices."""

    def _allow(self, action: str, resource: str) -> bool:
        from app.shared.authorization.enforcer import get_enforcer
        return get_enforcer().enforce("support_admin", resource, action)

    def test_can_read_user(self):
        assert self._allow("read", "User")

    def test_can_read_service(self):
        assert self._allow("read", "Service")

    def test_can_read_service_ticket(self):
        assert self._allow("read", "ServiceTicket")

    def test_can_write_service_ticket(self):
        assert self._allow("write", "ServiceTicket")

    def test_can_delete_service_ticket(self):
        assert self._allow("delete", "ServiceTicket")

    def test_can_read_ecosystem_ticket(self):
        assert self._allow("read", "EcosystemTicket")

    def test_can_write_ecosystem_ticket(self):
        assert self._allow("write", "EcosystemTicket")

    def test_can_delete_ecosystem_ticket(self):
        assert self._allow("delete", "EcosystemTicket")

    def test_cannot_access_role(self):
        assert not self._allow("read", "Role")

    def test_cannot_write_user(self):
        assert not self._allow("write", "User")

    def test_cannot_access_administrator(self):
        assert not self._allow("read", "Administrator")
