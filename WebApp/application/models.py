from application import db, app
from flask_login import UserMixin
import jwt
from datetime import datetime, timedelta

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Stores the user id of user who made the prediction
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    image = db.Column(db.LargeBinary, nullable=False)
    DL_model = db.Column(db.String, nullable=False)
    prediction = db.Column(db.String, nullable=False)
    probability = db.Column(db.Float, nullable=False)
    predicted_on = db.Column(db.DateTime, nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    # Stores the relationship between user and prediction
    user = db.relationship('Entry', backref='user', lazy=True)

    # Generates a token to reset password
    def get_reset_password_token(self, expires_in=1800):
        encoded = jwt.encode({'reset_password': self.id, 'exp': datetime.utcnow() + timedelta(seconds=expires_in)},
                          app.config['SECRET_KEY'], algorithm='HS256')
        return encoded
    
    # Function to verify the token and returns the user id
    # Converts function to be static method
    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)