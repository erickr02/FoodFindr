from sqlalchemy import Index
from flask_sqlalchemy import SQLAlchemy
from geoalchemy2 import Geography
from geoalchemy2.shape import to_shape
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()


# Remember to limit array sizes in actual code
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    verification_key = db.Column(db.String(100), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    first = db.Column(db.String(50), nullable=True)
    last = db.Column(db.String(50), nullable=True)
    favorite_foods = db.Column(db.JSON, nullable=True, default=[])
    liked_cuisines = db.Column(db.JSON, nullable=True, default=[])
    disliked_cuisines = db.Column(db.JSON, nullable=True, default=[])
    liked_rests = db.Column(db.JSON, nullable=True, default=[])
    disliked_rests = db.Column(db.JSON, nullable=True, default=[])
    interested = db.Column(db.JSON, nullable=True, default=[])
    recently_ordered = db.Column(db.JSON, nullable=True, default=[])
    saved_addresses = db.Column(db.JSON, nullable=True, default=[])
    cuisine_weights = db.Column(JSONB, nullable=True, default=dict)
    flavor_weights = db.Column(JSONB, nullable=True, default=dict)

    __table_args__ = (
        Index('idx_email', 'email'),
    )

    def __repr__(self):
        return f'<User {self.email}>'

# Not sure if restaurant schema will be needed, probably not
class Restaurant(db.Model):
    __tablename__ = 'restaurants'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.JSON, nullable=False, default={})
    hours = db.Column(db.JSON, nullable=True, default=[])
    summary = db.Column(db.JSON, nullable=True, default={})
    place_id = db.Column(db.String(100), unique=True, nullable=False)
    price_level = db.Column(db.String(50), nullable=True)
    end_price = db.Column(db.JSON, nullable=True, default={})
    start_price = db.Column(db.JSON, nullable=True, default={})
    rating = db.Column(db.Float, nullable=True)
    review_summary = db.Column(db.JSON, nullable=True, default={})
    types = db.Column(db.JSON, nullable=True, default=[])
    user_rating_count = db.Column(db.Integer, nullable=True)
    website = db.Column(db.String(200), nullable=True)

    location = db.Column(Geography(geometry_type='POINT', srid=4326), nullable=False)

    __table_args__ = (
        Index('idx_places_id', 'place_id'),
    )

    def __repr__(self):
        return f'<Restaurant {self.place_id}>'

    def get_lat_lng(self):
        point = to_shape(self.location)
        return point.y, point.x  # Returns (latitude, longitude)