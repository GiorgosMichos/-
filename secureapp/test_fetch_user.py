
from supabase_py import create_client, Client
import os

SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://****.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', '*****')

# Initialize Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Email to fetch (match exactly as it is in the database)
email = 'giorgos@petros.com'

# Fetch user by email
response = supabase.table('users').select('*').eq('email', email).execute()

# Print the query response
print(f"Query response: {response}")
print(f"User data retrieved: {response.get('data', [])}")
