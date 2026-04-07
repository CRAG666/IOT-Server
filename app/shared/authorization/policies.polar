actor CurrentUser {}

# Master administrator
allow(user: CurrentUser, _action, _resource) if
    user.account_type = "administrator" and
    user.is_master = true;

# Administrator
allow(user: CurrentUser, action, _resource: Manager) if
    user.account_type = "administrator" and
    not user.is_master and
    action in ["read", "write", "delete"];

allow(user: CurrentUser, action, _resource: User) if
    user.account_type = "administrator" and
    not user.is_master and
    action in ["read", "write", "delete"];

allow(user: CurrentUser, action, _resource: Device) if
    user.account_type = "administrator" and
    not user.is_master and
    action in ["read", "write", "delete"];

allow(user: CurrentUser, action, _resource: Application) if
    user.account_type = "administrator" and
    not user.is_master and
    action in ["read", "write", "delete"];

allow(user: CurrentUser, action, _resource: Service) if
    user.account_type = "administrator" and
    not user.is_master and
    action in ["read", "write", "delete"];

allow(user: CurrentUser, action, _resource: Ticket) if
    user.account_type = "administrator" and
    not user.is_master and
    action in ["read", "write"];

allow(user: CurrentUser, "read", _resource: Administrator) if
    user.account_type = "administrator" and
    not user.is_master;

# Manager
allow(user: CurrentUser, action, _resource: Manager) if
    user.account_type = "manager" and
    action in ["read", "write"];

allow(user: CurrentUser, action, _resource: User) if
    user.account_type = "manager" and
    action in ["read", "write"];

allow(user: CurrentUser, action, _resource: Device) if
    user.account_type = "manager" and
    action in ["read", "write"];

allow(user: CurrentUser, action, _resource: Ticket) if
    user.account_type = "manager" and
    action in ["read", "write"];

allow(user: CurrentUser, "read", _resource: Service) if
    user.account_type = "manager";

allow(user: CurrentUser, "read", _resource: Application) if
    user.account_type = "manager";

# User
allow(user: CurrentUser, "read", _resource: Device) if
    user.account_type = "user";

allow(user: CurrentUser, action, _resource: Ticket) if
    user.account_type = "user" and
    action in ["read", "write"];

allow(user: CurrentUser, "write", resource: User) if
    user.account_type = "user" and
    resource.id = user.account_id;

# Shared permissions
allow(user: CurrentUser, "write", resource) if
    resource.id = user.account_id and
    user.account_type in ["administrator", "manager", "user"];
