from sqlalchemy import inspect
from server import app, db, User  # Replace "your_module" with the correct module name

# Create an application context
with app.app_context():
    # Create an inspector object
    inspector = inspect(db.engine)

    # Check if the User table exists
    if inspector.has_table(User.__tablename__):
        print("User table exists in the database.")
    else:
        print("User table does not exist in the database.")