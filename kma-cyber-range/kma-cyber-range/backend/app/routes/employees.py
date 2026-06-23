from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.threat_logger import write_threat_event
from app.security_logger import write_auth_event
from app.security_event_service import write_security_event
from app.database import get_db
from app.models import Employee, User
from app.schemas import EmployeeCreate, EmployeeUpdate, ProfileUpdateRequest
from app.security import get_current_user, require_roles

router = APIRouter(tags=["Employees"])


def employee_to_dict(employee: Employee):
    return {
        "id": employee.id,
        "user_id": employee.user_id,
        "full_name": employee.full_name,
        "department": employee.department,
        "position": employee.position,
        "salary": employee.salary,
        "phone": employee.phone,
        "email": employee.email,
        "created_at": employee.created_at.isoformat() if employee.created_at else None,
        "updated_at": employee.updated_at.isoformat() if employee.updated_at else None,
    }


def set_auth_context(request: Request, current_user: dict):
    request.state.user_id = current_user["id"]
    request.state.username = current_user["username"]
    request.state.role = current_user["role"]
    request.state.jti = current_user.get("jti")

@router.get("/api/v1/employees")
def list_employees(
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin", "manager"]))
):
    set_auth_context(request, current_user)

    employees = db.query(Employee).order_by(Employee.id.asc()).all()

    request.state.security_message = "Employee list requested from PostgreSQL"

    write_security_event(
        event="employee_view",
        severity="low",
        user=current_user["username"],
        ip=request.client.host,
        details="employee_list"
    )

    return {
        "count": len(employees),
        "employees": [employee_to_dict(emp) for emp in employees]
    }


@router.get("/api/v1/employees/me")
def get_my_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    set_auth_context(request, current_user)

    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    employee = db.query(Employee).filter(Employee.user_id == user.id).first()

    if not employee:
        raise HTTPException(status_code=404, detail="Employee profile not found")

    request.state.security_message = "Current employee profile requested"

    return employee_to_dict(employee)


@router.get("/api/v1/employees/{employee_id}")
def get_employee_by_id(
    employee_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    BOLA Lab Endpoint.

    Cách đúng:
    - Admin/manager được xem tất cả.
    - Employee chỉ được xem hồ sơ của chính mình.

    Cách cố tình sai trong lab:
    - Chỉ cần có JWT hợp lệ là được xem bất kỳ employee_id nào.
    - Nếu employee thường xem hồ sơ không thuộc về mình, backend vẫn trả dữ liệu
      nhưng ghi log detected_attack = bola_attempt.
    """

    set_auth_context(request, current_user)

    employee = db.query(Employee).filter(Employee.id == employee_id).first()

    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    current_role = current_user.get("role")
    current_user_id = current_user.get("id")

    is_owner = employee.user_id == current_user_id
    is_privileged = current_role in ["admin", "manager"]

    if not is_owner and not is_privileged:
        request.state.detected_attack = "bola_attempt"

        write_threat_event(
            attack="bola_attempt",
            severity="high",
            user=current_user["username"],
            ip=request.client.host,
            mitre="T1190"
        )

        request.state.mitre_technique = "T1190"
        request.state.security_message = (
            f"BOLA attempt detected. "
            f"Authenticated user '{current_user.get('username')}' "
            f"requested employee_id={employee_id} "
            f"owned by user_id={employee.user_id}."
)

    else:
        request.state.detected_attack = "none"
        request.state.mitre_technique = None

        if is_owner:
            request.state.security_message = (
                f"Employee viewed own profile: employee_id={employee_id}"
            )

        else:
            request.state.security_message = (
                f"Privileged user viewed employee profile: employee_id={employee_id}"
            )

    # Cố tình vẫn trả dữ liệu dù phát hiện BOLA.
    # Đây là intentional vulnerability cho Cyber Range.

    if not is_owner and not is_privileged:

        write_security_event(
            event="bola_attempt",
            severity="high",
            user=current_user["username"],
            ip=request.client.host,
            details=(
                f"user_id={current_user_id}, "
                f"employee_id={employee_id}"
            )
        )

    else:

        write_security_event(
            event="employee_view",
            severity="low",
            user=current_user["username"],
            ip=request.client.host,
            details=f"employee_id={employee_id}"
        )

    return employee_to_dict(employee)

@router.post("/api/v1/employees")
def create_employee(
    data: EmployeeCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

    if data.user_id is not None:
        user = db.query(User).filter(User.id == data.user_id).first()
        if not user:
            raise HTTPException(status_code=400, detail="user_id does not exist")

    employee = Employee(
        user_id=data.user_id,
        full_name=data.full_name,
        department=data.department,
        position=data.position,
        salary=data.salary,
        phone=data.phone,
        email=data.email
    )

    db.add(employee)
    db.commit()
    db.refresh(employee)

    request.state.security_message = f"Employee created: employee_id={employee.id}"

    write_security_event(
        event="employee_created",
        severity="medium",
        user=current_user["username"],
        ip=request.client.host,
        details=f"employee_id={employee.id}"
    )

    return {
        "message": "Employee created successfully",
        "employee": employee_to_dict(employee)
    }

@router.patch("/api/v1/employees/profile")
def update_my_profile_mass_assignment(
    data: ProfileUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Mass Assignment Lab Endpoint.

    Cách đúng:
    - Employee chỉ được cập nhật full_name, phone, email.

    Cách cố tình sai trong lab:
    - Backend chấp nhận cả field role từ client.
    - Nếu client gửi {"role": "admin"}, hệ thống cập nhật role của user thành admin.
    """

    set_auth_context(request, current_user)

    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    employee = db.query(Employee).filter(Employee.user_id == user.id).first()

    if not employee:
        raise HTTPException(status_code=404, detail="Employee profile not found")

    if data.full_name is not None:
        employee.full_name = data.full_name

    if data.phone is not None:
        employee.phone = data.phone

    if data.email is not None:
        employee.email = data.email

    # Intentional vulnerability: Mass Assignment
    if data.role is not None:
        old_role = user.role
        user.role = data.role

        write_auth_event(
            event="role_change_attempt",
            actor=current_user["username"],
            target=user.username,
            result=f"{old_role}_to_{data.role}",
            ip=request.client.host,
            details="mass_assignment_endpoint"
        )

        write_security_event(
            event="employee_role_change_attempt",
            severity="medium",
            user=current_user["username"],
            ip=request.client.host,
            details=f"{old_role}->{data.role}"
        )

        if data.role == "admin" and old_role != "admin":

            write_auth_event(
                event="privilege_escalation",
                actor=current_user["username"],
                target=user.username,
                result="success",
                ip=request.client.host,
                details=f"{old_role}->{data.role}",
                severity="high"
            )

            write_security_event(
                event="privilege_escalation",
                severity="high",
                user=current_user["username"],
                ip=request.client.host,
                details=f"{old_role}->{data.role}"
            )

            request.state.detected_attack = "mass_assignment_role_escalation"

            write_threat_event(
                attack="mass_assignment_role_escalation",
                severity="high",
                user=current_user["username"],
                ip=request.client.host,
                mitre="T1078"
            )

            request.state.mitre_technique = "T1078"
            request.state.security_message = (
            	f"Mass Assignment attempt: user={user.username} changed role "
             	f"from {old_role} to {data.role}"
            )

        else:
             write_auth_event(
                 event="role_change",
                 actor=current_user["username"],
                 target=user.username,
                 result="success",
                 ip=request.client.host,
                 details=f"{old_role}->{data.role}",
                 severity="medium"
             )

             request.state.detected_attack = "mass_assignment_role_update"
             request.state.mitre_technique = "T1078"
             request.state.security_message = (
             	f"Mass Assignment role field accepted: user={user.username}, "
                f"old_role={old_role}, new_role={data.role}"
             )
    else:
        request.state.detected_attack = "none"
        request.state.mitre_technique = None
        request.state.security_message = "Employee profile updated normally"

    db.commit()
    db.refresh(user)
    db.refresh(employee)

    return {
        "message": "Profile updated",
        "profile": {
            "employee_id": employee.id,
            "user_id": user.id,
            "username": user.username,
            "full_name": employee.full_name,
            "phone": employee.phone,
            "email": employee.email,
            "role": user.role
        },
        "lab_note": "This endpoint intentionally accepts role field for Mass Assignment demonstration."
    }

@router.patch("/api/v1/employees/{employee_id}")
def update_employee(
    employee_id: int,
    data: EmployeeUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

    employee = db.query(Employee).filter(Employee.id == employee_id).first()

    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    update_data = data.dict(exclude_unset=True)

    if "user_id" in update_data and update_data["user_id"] is not None:
        user = db.query(User).filter(User.id == update_data["user_id"]).first()
        if not user:
            raise HTTPException(status_code=400, detail="user_id does not exist")

    for field, value in update_data.items():
        setattr(employee, field, value)

    db.commit()
    db.refresh(employee)

    request.state.security_message = f"Employee updated: employee_id={employee_id}"

    write_security_event(
        event="employee_updated",
        severity="medium",
        user=current_user["username"],
        ip=request.client.host,
        details=f"employee_id={employee_id}"
    )

    return {
        "message": "Employee updated successfully",
        "employee": employee_to_dict(employee)
    }


@router.delete("/api/v1/employees/{employee_id}")
def delete_employee(
    employee_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

    employee = db.query(Employee).filter(Employee.id == employee_id).first()

    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    db.delete(employee)
    db.commit()

    request.state.security_message = f"Employee deleted: employee_id={employee_id}"

    write_security_event(
        event="employee_deleted",
        severity="high",
        user=current_user["username"],
        ip=request.client.host,
        details=f"employee_id={employee_id}"
    )

    return {
        "message": "Employee deleted successfully",
        "employee_id": employee_id
    }


@router.get("/api/v1/departments")
def list_departments(request: Request):
    request.state.security_message = "Departments listed"

    return {
        "departments": [
            {"id": 1, "name": "Board"},
            {"id": 2, "name": "Human Resources"},
            {"id": 3, "name": "Information Technology"},
            {"id": 4, "name": "Security Operations"},
            {"id": 5, "name": "Finance"},
            {"id": 6, "name": "Legal"}
        ]
    }
