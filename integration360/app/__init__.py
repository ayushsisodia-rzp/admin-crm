from flask import Flask
import os
import psycopg2
from psycopg2 import pool

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']

# Setup PostgreSQL connection pool
postgresql_pool = psycopg2.pool.SimpleConnectionPool(
    minconn=app.config['PG_POOL_MIN'],
    maxconn=app.config['PG_POOL_MAX'],
    user=app.config['PG_USER'],
    password=app.config['PG_PASSWORD'],
    host=app.config['PG_HOST'],
    port=app.config['PG_PORT'],
    database=app.config['PG_DBNAME']
)

app.postgresql_pool = postgresql_pool

def connect_db():
    try:
        return app.postgresql_pool.getconn()
    except Exception as e:
        print(f"🔥 Error connecting to PostgreSQL: {e}")
        raise

# Flask-Login setup
from flask_login import LoginManager
from app.models import User

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    conn = connect_db()
    try:
        with conn.cursor() as c:
            c.execute('SELECT id, username, role FROM users WHERE id = %s', (user_id,))
            user_data = c.fetchone()
            if user_data:
                return User(id=user_data[0], username=user_data[1], role=user_data[2])
            return None
    except Exception as e:
        print(f"Error loading user: {e}")
        return None
    finally:
        app.postgresql_pool.putconn(conn)

from app import routes  # Import routes after app and login manager setup
