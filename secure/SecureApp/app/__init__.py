from flask import Flask, send_from_directory
from supabase import create_client, Client
import os

app = Flask(__name__, static_folder='static')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')


# Supabase configuration
SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://vnpwrbzydaohhowhqgpa.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZucHdyYnp5ZGFvaGhvd2hxZ3BhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjYyMTQ4MDUsImV4cCI6MjA0MTc5MDgwNX0.HCyEYtAlOYEbkIfkAe6M3gnLWieyxwgvjG5nU5gs4pk')

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory('static/uploads', filename)
    except FileNotFoundError:
        return "File not found", 404


from app import routes
