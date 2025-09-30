from models import db, User, Restaurant
from foodfindr import app

with app.app_context():
    db.create_all()
    # Create an index on the username column
    db.Index('idx_email', User.email)
    db.Index('idx_places_id', Restaurant.place_id)
