from models import User, db
from werkzeug.security import generate_password_hash

# Create a new admin user. Adjust the email below as needed.
admin = User(username="admin", email="bb2010ng@gmail.com")
admin.password_hash = generate_password_hash("your_admin_password")
db.session.add(admin)
db.session.commit()
