from supabase import create_client, Client
import os
from datetime import datetime

SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://vnpwrbzydaohhowhqgpa.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZucHdyYnp5ZGFvaGhvd2hxZ3BhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjYyMTQ4MDUsImV4cCI6MjA0MTc5MDgwNX0.HCyEYtAlOYEbkIfkAe6M3gnLWieyxwgvjG5nU5gs4pk')

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# User class interacting with Supabase
class User:
    def __init__(self, id=None, username=None, email=None, password=None, role="user", date_created=None):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.date_created = date_created or datetime.utcnow()

    @staticmethod
    def create_user(username, email, password, role="user"):
        data = {
            "username": username,
            "email": email,
            "password": password,  # Consider hashing the password here
            "role": role,
            "date_created": datetime.utcnow()
        }
        result = supabase.table('users').insert(data).execute()
        return result

    @staticmethod
    def get_user_by_email(email):
        result = supabase.table('users').select("*").eq("email", email).execute()
        return result.data

    @staticmethod
    def update_user_role(user_id, new_role):
        result = supabase.table('users').update({"role": new_role}).eq("id", user_id).execute()
        return result

    def __repr__(self):
        return f"<User {self.username}>"

# AuditLog class interacting with Supabase
class AuditLog:
    def __init__(self, id=None, user_id=None, action=None, timestamp=None):
        self.id = id
        self.user_id = user_id
        self.action = action
        self.timestamp = timestamp or datetime.utcnow()

    @staticmethod
    def create_log(user_id, action):
        data = {
            "user_id": user_id,
            "action": action,
            "timestamp": datetime.utcnow()
        }
        result = supabase.table('audit_logs').insert(data).execute()
        return result

    @staticmethod
    def get_logs_for_user(user_id):
        result = supabase.table('audit_logs').select("*").eq("user_id", user_id).execute()
        return result.data

    def __repr__(self):
        return f"<AuditLog {self.action} by User {self.user_id} at {self.timestamp}>"
