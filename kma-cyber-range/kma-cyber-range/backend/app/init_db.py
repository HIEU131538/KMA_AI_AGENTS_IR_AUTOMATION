import time

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.models import Employee, User
from app.security import hash_password


def wait_for_database(max_retries: int = 30, delay: int = 2):
    for attempt in range(1, max_retries + 1):
        try:
            connection = engine.connect()
            connection.close()
            print("[DB] PostgreSQL is ready.")
            return
        except OperationalError:
            print(f"[DB] PostgreSQL is not ready. Retry {attempt}/{max_retries}...")
            time.sleep(delay)

    raise RuntimeError("[DB] Could not connect to PostgreSQL.")


def create_tables():
    Base.metadata.create_all(bind=engine)
    print("[DB] Tables created successfully.")


def seed_users_and_employees(db: Session):
    existing_admin = db.query(User).filter(User.username == "admin").first()

    if existing_admin:
        print("[DB] Seed data already exists. Skipping seed.")
        return

    admin = User(
        username="admin",
        hashed_password=hash_password("admin123"),
        role="admin",
        is_active=True
    )

    employee01 = User(
        username="employee01",
        hashed_password=hash_password("employee123"),
        role="employee",
        is_active=True
    )

    manager01 = User(
        username="manager01",
        hashed_password=hash_password("manager123"),
        role="manager",
        is_active=True
    )

    db.add_all([admin, employee01, manager01])
    db.commit()

    db.refresh(admin)
    db.refresh(employee01)
    db.refresh(manager01)

    employees = [
        Employee(
            user_id=admin.id,
            full_name="Duong Ngoc Hieu",
            department="Board",
            position="Director",
            salary=50000000,
            phone="0900000001",
            email="admin@kma.local"
        ),
        Employee(
            user_id=employee01.id,
            full_name="Nguyen Quang Dat",
            department="Human Resources",
            position="HR Officer",
            salary=20000000,
            phone="0900000002",
            email="employee01@kma.local"
        ),
        Employee(
            user_id=manager01.id,
            full_name="Nguyen Minh Tan",
            department="Information Technology",
            position="IT Manager",
            salary=35000000,
            phone="0900000003",
            email="manager01@kma.local"
        )
    ]

    db.add_all(employees)
    db.commit()

    print("[DB] Seed users and employees created successfully.")


def init_database():
    wait_for_database()
    create_tables()

    db = SessionLocal()

    try:
        seed_users_and_employees(db)
    finally:
        db.close()
