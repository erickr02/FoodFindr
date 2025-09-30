from flask import Flask, session, render_template, redirect, url_for, jsonify, request, make_response
import flask
import jwt as jwtdecode
from flask_jwt_extended import JWTManager, create_access_token
from models import db, User, Restaurant
import smtplib
from email.message import EmailMessage
from urllib.parse import quote
import string
import random
import os
import bcrypt
import pandas as pd
from dotenv import load_dotenv
import requests
from service import create_service, get_credentials
import json


load_dotenv()
google = os.getenv('GOOGLE_KEY')

app = Flask(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"

app.config["JWT_SECRET_KEY"] = "balls"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60 * 60 * 24 # 1 day
jwt = JWTManager(app)

app.config['SECRET_KEY'] = 'foodfindr'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://foodfindr:foodfindr@localhost:5432/foodfindrdb'

db.init_app(app)

# Create service ??????
client_secret_file = 'client-secret.json'
API_NAME = 'places'
API_VERSION = 'v1'
SCOPES = ['https://www.googleapis.com/auth/cloud-platform']

service = create_service(client_secret_file, API_NAME, API_VERSION, SCOPES)

def drop_tables():
    # Drop all tables and create new ones
    # db.drop_all()
    # db.create_all()
    User.__table__.drop(db.engine, checkfirst=True)
    db.create_all()
    
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
    # If there is any problem checking the auth, just redirect to login page
    try:
        response, status_code = check_auth()
        # If user is not logged in, redirect to login page, else redirect to rec page
        if status_code != 201:
            return render_template('login.html')
        user = User.query.filter_by(email=session['email']).first()
        if not user.first:
            return render_template('home.html', intro=True, email=session['email'])
    except Exception as e:
        print(f"Error checking auth: {e}")
        return render_template('login.html')
    
    return render_template('home.html', intro=False, email=session['email'])

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
    elif not user.verified:
        return jsonify(status="ERROR", error=True, message="Account not verified. Please check your email for the verification link."), 401
    
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
    # Destroy session, return to log in page
    session.clear()
    response = make_response(jsonify(status="OK", error=False, message="Logged out successfully."))
    response.delete_cookie('token')
    return response

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

# Compare stored verify key to one given
@app.route('/api/verify', methods=['GET'])
def verify():
    email = request.args.get('email')
    key = request.args.get('key')

    if not email or not key:
        return render_template('verify.html', status="ERROR", error=True, message="Email or key not provided."), 401
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
    if not request or not request.cookies:
        return jsonify(status="ERROR", error=True, message="User is not logged in."), 401
    token = request.cookies.get('token')  # Extracts 'token' cookie
    decoded_token = None
    if token:
        try:
            # If the token is valid, decode it and store email in json response
            decoded_token = jwtdecode.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            return jsonify(status="OK", error=False, message="User is logged in", email=decoded_token.get('sub')), 201
        except jwtdecode.ExpiredSignatureError:
            # If the token has expired, return an error message
            return jsonify(status="ERROR", error=True, message="Token has expired. Please log in again."), 40
    else:
        return jsonify(status="ERROR", error=True, message="User is not logged in."), 401

@app.route('/api/set-location', methods=['POST'])
def set_location():
    data = request.get_json()
    lat = data['latitude']
    lon = data['longitude']
    # Store the location in the user's session or database
    session['location'] = {'latitude': lat, 'longitude': lon}
    return jsonify(status="OK", error=False, message="Location set successfully."), 201

@app.route('/api/get-restaurants', methods=['GET'])
def get_restaurants(intent=None):
    # Retrieve user's location from session
    # Jitter user's location to find restaurants in a grid around their location
    lat = session['location']['latitude']
    lon = session['location']['longitude']
    jitter = 0.005

    locations = [
        [lat, lon],
        # [lat + jitter, lon],
        # [lat - jitter, lon],
        # [lat, lon + jitter],
        # [lat, lon - jitter],
        # [lat + jitter, lon + jitter],
        # [lat - jitter, lon - jitter],
        # [lat + jitter, lon - jitter],
        # [lat - jitter, lon + jitter]
    ]
    creds = get_credentials(client_secret_file, SCOPES)
    access_token = creds.token
    url = "https://places.googleapis.com/v1/places:searchNearby"

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'X-Goog-FieldMask': '*'
    }

    # Exclude all the bullshit places that are not primarily restaurants
    if intent:
        # Construct payload based on intent ######
        pass
    else:
        payload = {
            'includedTypes': ['restaurant'],
            'excludedTypes': ["supermarket", "butcher_shop", "grocery_store", "video_arcade", "fitness_center", "gym", "sports_complex", "sports_activity_location", "amusement_center"],
            'maxResultCount': 20,
            'locationRestriction':{
                'circle': {
                    'center': {
                        'latitude': session['location']['latitude'],
                        'longitude': session['location']['longitude']
                    },
                    'radius': 5000
                }
            }
        }
    
    places = []
    for location in locations:
        payload['locationRestriction']['circle']['center']['latitude'] = location[0]
        payload['locationRestriction']['circle']['center']['longitude'] = location[1]
        response = requests.post(url, headers=headers, json=payload)
        # print("Found locations for lat:", location[0], " lon:", location[1])
        if response.status_code != 200:
            return jsonify(status="ERROR", error=True, message="Failed to retrieve restaurants."), 500
    
        places.extend(response.json().get('places', []))

    cleaned = []
    seen = set()
    for place in places:
        # Filter out duplicates for simpler computation later
        if place.get('id') in seen:
            continue
        seen.add(place.get('id'))

        cleaned_rest = {
            'name': place['displayName']['text'],
            'address': place.get('formattedAddress', 'No address available'),
            'rating': place.get('rating', 'No rating available'),
            'userRatingCount': place.get('userRatingCount', 0),
            'price_level': place.get('price_level', 'No price level available'),
            'types': place.get('types', []),
            'place_id': place.get('id', 'No ID available'),
            # 'photos': place.get('photos', []),
            # 'reviews': place.get('reviews', []),
            'business_status': place.get('business_status', 'No status available'),
            'opening_hours': place.get('opening_hours', {}).get('open_now', False)
        }
        cleaned.append(cleaned_rest)
    
    res = recommend_restaurants(cleaned)
    return jsonify(status="OK", error=False, message="Balls", restaurants=[]), 201

@app.route('/api/input', methods=['POST'])
def handle_input():
    data = request.json
    query = data.get('query', '')
    if not query:
        return jsonify(status="ERROR", error=True, message="No query provided."), 401

    
    print(query)

    intent = {"action": None, "cuisine": None, "query": query}

    for cuisine in ["fast food", "italian", "chinese", "mexican", "japanese", "indian", "thai", "french", "mediterranean", "american", "korean", "vietnamese", "spanish", "turkish", "lebanese"]:
        if cuisine in query.lower():
            session['cuisine'] = cuisine
            break
    
    if any(word in query for word in ["find", "recommend", "suggest", "where", "restaurants", "eat", "dine", "food", "place to eat", "nearby", "near me", "close", "close by"]):
        intent['action'] = "search_restaurants"

    # Process the query and recommend restaurants
    return jsonify(status="OK", error=False), 201

# Function will try to filter out things that are not uniquely restaurants, like grocery stores etc, 
# Maybe this function will also filter out duplicates
def filter_rests(rests):
    for rest in rests:
        for t in rest['types']:
            if t not in ['restaurant', 'food', 'point_of_interest', 'establishment']:
                rests.remove(rest)
                break

def recommend_restaurants(rests):
    # This function will take in a list of restaurants and a set of user prefs/parameters to try to recommend the best restaurant
    prompt = "Give that the user is located at latitude " + str(session['location']['latitude']) + " and longitude " + str(session['location']['longitude']) + ", recommend a restaurant from the following list:\n"
    for rest in rests:
        prompt += f"- {rest['name']}, located at {rest['address']}, with a rating of {rest.get('rating', 'N/A')}, a user rating count of {rest.get('userRatingCount', 0)} and price level {rest.get('price_level', 'N/A')}.\n"
    prompt += "Rank the restaurants from best to worst based on the user's preferences, the popularity of the restaurant, and how close it is to the user. You do not need to provide any reasoning or numbers. Disregard duplicates. Return the only the restaurant names, do not number them at all, do not provide location."
    
    answer_text = query_ollama(prompt)

    # Print the text in terminal
    print("Ollama says:", answer_text)

    rest_names = answer_text.splitlines()
    print("REST NAMES")
    print(rest_names)
    # Return for frontend
    return jsonify({"recommendations": answer_text})

def query_ollama(prompt, model="mistral"):
    url = "http://localhost:11434/api/generate"
    headers = {"Content-Type": "application/json"}
    payload = {"model": model, "prompt": prompt}

    response = requests.post(url, json=payload, headers=headers, stream=True)

    full_text = ""

    for line in response.iter_lines():
        if line:
            try:
                data = json.loads(line.decode("utf-8"))
                # Each line has 'response' with a partial chunk of text
                chunk = data.get("response", "")
                full_text += chunk
            except json.JSONDecodeError:
                continue  # skip lines that throw errors ?

    return full_text

def user_question():
    pass


if __name__ == "__main__":
    with app.app_context():
        # drop_tables()
        # db.create_all()
        # db.Index('idx_email', User.email)
        pass
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)   