from sqlalchemy import Index
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    verification_key = db.Column(db.String(100), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    first = db.Column(db.String(50), nullable=True)
    last = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f'<User {self.email}>'
