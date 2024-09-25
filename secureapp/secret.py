import secrets

# Generate a new secret key
secret_key = secrets.token_hex(16)  # 32-character long secret key
print(f"Generated SECRET_KEY: {secret_key}")
