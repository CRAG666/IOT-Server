from app.shared.base_domain.controller import FullCrudApiController
from app.domain.device.schemas import DeviceCreate, DeviceResponse, DeviceUpdate
from app.domain.device.service import DeviceServiceDep
from app.shared.authorization.dependencies import require_read, require_write, require_delete
from app.database.model import Device


class DeviceController(FullCrudApiController):
    prefix = "/devices"
    tags = ["Devices"]
    service_dep = DeviceServiceDep
    response_schema = DeviceResponse
    create_schema = DeviceCreate
    update_schema = DeviceUpdate
    
    # OSO-based authorization - following the same declarative pattern
    list_dependencies = [require_read(Device)]
    retrieve_dependencies = [require_read(Device)]
    create_dependencies = [require_write(Device)]
    update_dependencies = [require_write(Device)]
    delete_dependencies = [require_delete(Device)]


device_router = DeviceController().router
