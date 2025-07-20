from sqlalchemy import Index
from flask_sqlalchemy import SQLAlchemy
from geoalchemy2 import Geography
from geoalchemy2.shape import to_shape
from sqlalchemy import func

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
    # address = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<User {self.email}>'

class Restaurant(db.Model):
    __tablename__ = 'restaurants'

    id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    hours = db.Column(db.Text, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    place_id = db.Column(db.String(100), unique=True, nullable=False)
    photos = db.Column(db.Text, nullable=True)  # Store as JSON string
    end_price = db.Column(db.Float, nullable=True)
    start_price = db.Column(db.Float, nullable=True)
    rating = db.Column(db.Float, nullable=True)
    review_summary = db.Column(db.Text, nullable=True)
    types = db.Column(db.Text, nullable=True)  # Store as JSON string
    user_rating_count = db.Column(db.Integer, nullable=True)
    website = db.Column(db.String(200), nullable=True)

    location = db.Column(Geography(geometry_type='POINT', srid=4326), nullable=False)

    def get_lat_lng(self):
        point = to_shape(self.location)
        return point.y, point.x  # Returns (latitude, longitude)