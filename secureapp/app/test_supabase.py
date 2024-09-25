from models import User

# Test creating a user
result = User.create_user(
    username="testuser",
    email="testuser@example.com",
    password="securepassword123",
    role="user"
)

print("Insert Result:", result)
