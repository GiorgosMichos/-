from supabase import create_client, Client
import os
from datetime import datetime

SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://mdeslfmtufjosscpogfe.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1kZXNsZm10dWZqb3NzY3BvZ2ZlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjcyMDIxNDcsImV4cCI6MjA0Mjc3ODE0N30.f8tLrFp6Fu90xYWT-YAqi4sH_DYjFtpCIUc50vVTgYU')

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class User:
    def __init__(self, id=None, username=None, email=None, password=None, role="user", date_created=None):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.date_created = date_created or datetime.utcnow().isoformat()

    @staticmethod
    def create_user(username, email, password, role="user"):
        data = {
            "username": username,
            "email": email,
            "password": password,  # This should be hashed before storing
            "role": role,
            "date_created": datetime.utcnow().isoformat()  # Converting datetime to string
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
        response = supabase.table('audit_logs').select("*").eq("user_id", user_id).execute()
        if response['error']:
            raise Exception(response['error'])
        return response['data']
        # Old code:
        # result = supabase.table('audit_logs').select("*").eq("user_id", user_id).execute()
        # return result.data

    def __repr__(self):
        return f"<AuditLog {self.action} by User {self.user_id} at {self.timestamp}>"
