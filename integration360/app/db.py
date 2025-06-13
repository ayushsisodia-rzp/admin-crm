import psycopg2
import os

def connect_db():
    """Establish a connection to the PostgreSQL database."""

    PG_USER = os.environ.get('PG_USER') or 'ayush'
    PG_PASSWORD = os.environ.get('PG_PASSWORD') or 'ayush'
    PG_HOST = os.environ.get('PG_HOST') or 'localhost'
    PG_PORT = os.environ.get('PG_PORT') or '5432'
    PG_DBNAME = os.environ.get('PG_DBNAME') or 'knowledge_crm'

    try:
        conn = psycopg2.connect(
            host=PG_HOST,
            database=PG_DBNAME,
            user=PG_USER,
            password=PG_PASSWORD
        )
        return conn
    except Exception as e:
        print(f"Error connecting to PostgreSQL: {e}")
        raise
