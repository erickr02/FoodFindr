from flask import Flask, session, render_template, redirect, url_for, jsonify, request, make_response
import flask
import jwt as jwtdecode
from flask_jwt_extended import JWTManager, create_access_token
from models import db, User
import smtplib
from email.message import EmailMessage
from urllib.parse import quote
import string
import random
import os
import bcrypt

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "balls"
jwt = JWTManager(app)

app.config['SECRET_KEY'] = 'foodfindr'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://foodfindr:foodfindr@localhost:5432/foodfindrdb'

db.init_app(app)

def drop_tables():
    # Drop all tables and create new ones
    db.drop_all()
    db.create_all()
    
    # Create the admin user
    # new_user = User(
    #     email="admin@gmail.com",
    #     password="admin"
    # )
    # db.session.add(new_user)
    # db.session.commit()   

def generate_key():
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(12))

def send_verification(email, key):
    base_url = "http://localhost/api/verify"

    encoded_email = quote(email)
    encoded_key = quote(key)

    link = f"Verification link for hw account creation: {base_url}?email={encoded_email}&key={encoded_key}"

    print(link)
    from_email = 'foodfindr@gmail.com'
    subject = "Email Verification"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = email
    msg.set_content(link)

    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)

# Landing page for website, if user is logged in, redirect to regular page, if they are not, redirect to login page
@app.route('/', methods=['GET'])
def landing():
    response, status_code = check_auth()
    # If user is not logged in, redirect to login page, else redirect to rec page
    if status_code != 201:
        return render_template('login.html')
    return render_template('rec.html')

# Register page for website
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/api/login', methods=['POST'])
def login():
    # Extract username and password from the request
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter_by(email=email).first()
    
    # If user does not exist, return error
    if not user:
        return jsonify(status="ERROR", error=True, message="Email not found"), 401
    
    # If user does exist, check if the password is correct
    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')) == False:
        return jsonify(status="ERROR", error=True, message="Password is incorrect."), 401
    
    access_token = create_access_token(identity=email)
    response = make_response(jsonify(status="OK", error=False, access_token=access_token))
    
    # Set token as an HTTP-only, Secure cookie
    response.set_cookie('token', value=access_token, 
                        #httponly=True,
                        path='/',
                        samesite='Strict',
                        )  
    session['email'] = email
    
    return response

@app.route('/api/logout', methods=['GET'])
def logout():
    pass

# NEED TO CHANGE THIS EVENTUALLY WHEN USERS MODEL IS UPDATED
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    password = data.get('password')
    email = data.get('email')
    key = generate_key()

    if not password or not email:
        return jsonify(status="ERROR", error=True, message="Required fields not provided."), 401

    # Store hashed pw
    password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    new_user = User(email=email, password=password, verification_key=key)
    db.session.add(new_user)
    db.session.commit()

    send_verification(email, key)

    return jsonify(status="OK", error=False, message="Registration successful!"), 201

@app.route('/api/verify', methods=['GET'])
def verify():
    email = request.args.get('email')
    key = request.args.get('key')

    if not email or not key:
        return render_template('verify.html', status="ERROR", error=True, message="Email or key not provided."), 401
    # Find the user with the associated email
    user = User.query.filter_by(email=email).first()

    if not user or user.verification_key != key:
        return render_template('verify.html', status="ERROR", error=True, message="Verification failed."), 401
    
    if user.verified:
        return render_template('verify.html', status="ERROR", error=True, message="Account already verified."), 401
    # If everything is okay up until now, verify the account
    user.verified = True
    db.session.commit()
    
    return render_template('verify.html', status="OK", error=False, message="Account verified successfully!"), 201
    
@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    # Function to check if the user is logged in
    token = request.cookies.get('token')  # Extracts 'token' cookie
    decoded_token = None
    if token:
        try:
            # If the token is valid, decode it and store username in json response
            decoded_token = jwtdecode.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            return jsonify(status="OK", error=False, message="User is logged in", email=decoded_token.get('sub')), 201
        except jwtdecode.ExpiredSignatureError:
            # If the token has expired, return an error message
            return jsonify(status="ERROR", error=True, message="Token has expired. Please log in again."), 401

if __name__ == "__main__":
    with app.app_context():
        # drop_tables()
        # db.create_all()
        # db.Index('idx_email', User.email)
        pass
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)