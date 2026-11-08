"""Create the first administrator interactively after database migrations."""
import getpass
from sqlalchemy import select
from app.database import SessionLocal
from app.models.entities import User, UserRole
from app.security import hash_password

def main():
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            raise SystemExit("An account already exists. Use an administrator account to create users.")
        email = input("Administrator email: ").strip().lower()
        password = getpass.getpass("Password (minimum 12 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise SystemExit("Passwords do not match.")
        user = User(email=email, password_hash=hash_password(password), role=UserRole.admin)
        db.add(user)
        db.commit()
        print(f"Administrator created: {email}")

if __name__ == "__main__":
    main()
