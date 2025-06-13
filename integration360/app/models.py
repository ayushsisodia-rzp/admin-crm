from flask_login import UserMixin
from werkzeug.security import check_password_hash
from app import app

class User(UserMixin):

    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

    @staticmethod
    def validate(username, password):
        conn = app.postgresql_pool.getconn()
        try:
            with conn.cursor() as c:
                c.execute('SELECT id, username, password, role FROM users WHERE username = %s', (username,))
                user_data = c.fetchone()
                if user_data and check_password_hash(user_data[2], password):
                    return User(id=user_data[0], username=user_data[1], role=user_data[3])
                return None
        except Exception as e:
            print(f"Error validating user: {e}")
            return None
        finally:
            app.postgresql_pool.putconn(conn)


