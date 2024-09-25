from flask import Flask, send_from_directory
from supabase import create_client, Client

import os

app = Flask(__name__, static_folder='static')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '7c2c2be5094a7a7372bd49f7ed11c72e')


# Supabase configuration
SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://mdeslfmtufjosscpogfe.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1kZXNsZm10dWZqb3NzY3BvZ2ZlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjcyMDIxNDcsImV4cCI6MjA0Mjc3ODE0N30.f8tLrFp6Fu90xYWT-YAqi4sH_DYjFtpCIUc50vVTgYU')

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory('static/uploads', filename)
    except FileNotFoundError:
        return "File not found", 404


from app import routes

