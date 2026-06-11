from sqlalchemy import text
from sqlmodel import Session

VIEWS: dict[str, str] = {
    "device_manager_vw": """
        CREATE OR REPLACE VIEW device_manager_vw AS
        SELECT DISTINCT
            d.id AS device_id,
            m.id AS manager_id
        FROM device d
        JOIN device_service ds ON d.id = ds.device_id
        JOIN manager_service ms ON ds.service_id = ms.service_id
        JOIN manager m ON ms.manager_id = m.id
    """,
    "user_manager_vw": """
        CREATE OR REPLACE VIEW user_manager_vw AS
        SELECT DISTINCT
            u.id AS user_id,
            m.id AS manager_id
        FROM "user" u
        JOIN user_role ur ON u.id = ur.user_id
        JOIN role r ON ur.role_id = r.id
        JOIN manager_service ms ON r.service_id = ms.service_id
        JOIN manager m ON ms.manager_id = m.id
    """,
    "service_manager_vw": """
        CREATE OR REPLACE VIEW service_manager_vw AS
        SELECT DISTINCT
            s.id AS service_id,
            m.id AS manager_id
        FROM service s
        JOIN manager_service ms ON s.id = ms.service_id
        JOIN manager m ON ms.manager_id = m.id
    """,
    "application_manager_vw": """
        CREATE OR REPLACE VIEW application_manager_vw AS
        SELECT DISTINCT
            a.id AS application_id,
            m.id AS manager_id
        FROM application a
        JOIN application_service asrv ON a.id = asrv.application_id
        JOIN manager_service ms ON asrv.service_id = ms.service_id
        JOIN manager m ON ms.manager_id = m.id
    """,
    "ticket_manager_vw": """
        CREATE OR REPLACE VIEW ticket_manager_vw AS
        SELECT DISTINCT
            et.id AS ticket_id,
            m.id AS manager_id
        FROM ecosystem_ticket et
        JOIN manager_service ms ON et.manager_service_id = ms.id
        JOIN manager m ON ms.manager_id = m.id
    """,
}


def create_views(session: Session) -> None:
    is_sqlite = session.bind.dialect.name == "sqlite"  # type: ignore[union-attr]
    for view_name, view_sql in VIEWS.items():
        if is_sqlite:
            session.exec(text(f"DROP VIEW IF EXISTS {view_name}"))
            view_sql = view_sql.replace("CREATE OR REPLACE VIEW", "CREATE VIEW")
        session.exec(text(view_sql))
    session.commit()
