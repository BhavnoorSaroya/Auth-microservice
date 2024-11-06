from flask import Flask, request, jsonify, make_response, redirect
from flask_cors import CORS
import jwt
import time
import os
import requests
from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load the private key for signing tokens
private_key = None
public_key = None

if private_key is None:
    with open('private.pem', 'r') as f:
        private_key = f.read()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration for the User Service and email
# USER_SERVICE_URL = 'http://localhost:5001'
USER_SERVICE_URL = 'https://isa-upms.azurewebsites.net'
SENDGRID_USERNAME = 'apikey'  # Use 'apikey' as the username for SendGrid SMTP
EMAIL_SENDER = 'overlord@saroya.dev'  # Set your email
SMTP_SERVER = 'smtp.sendgrid.net'  # Replace with your SMTP server
SMTP_PORT = 587
with open('api.key', 'r') as f:
        SENDGRID_API_KEY = f.read()
EMAIL_PASSWORD = SENDGRID_API_KEY


# Utility function to create a JWT token using RS256
def create_jwt(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='RS256')

# Alternatively, for the entire app, add a global options handler
@app.before_request
def before_request():
    if request.method == 'OPTIONS':
        response = jsonify({"message": "Preflight OK"})
        response.headers['Access-Control-Allow-Origin'] = 'https://isa-facade.azurewebsites.net'
        # response.headers['Access-Control-Allow-Origin'] = 'localhost:5000'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.status_code = 200
        return response

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')


    # Verify user with the User Service
    user_service_url = f"{USER_SERVICE_URL}/login"
    response = requests.post(user_service_url, json={'email': email, 'password': password})

    if response.status_code == 200:
        # Generate JWT token on successful authentication
        payload = {'email': email, 'exp': time.time() + 3600}
        token = create_jwt(payload, private_key)
        
        # Set token in HTTP-only cookie
        response = make_response(jsonify({'token': token}))
        response.headers['Access-Control-Allow-origin'] = 'https://isa-facade.azurewebsites.net'
        response.set_cookie(
            'jwt', token, httponly=True, secure=True, samesite='None'
        )
        return response
    return jsonify({'message': 'Invalid credentials'}), 401

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    form = request.form
    email = form.get('email')
    if email is None:
        email = data.get('email')
    password = form.get('password')
    if password is None:
        password = data.get('password')

    user_service_url = f"{USER_SERVICE_URL}/register"
    response = requests.post(user_service_url, json={'email': email, 'password': password}, body={'email': email, 'password': password})

    if response.status_code == 201:
        return redirect('https://isa-facade.azurewebsites.net/message?message="Registered Successfully"', code=304)
    return jsonify(response.json()), response.status_code

# Route to send a password reset email
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    form = request.form
    email = data.get('email') 
    if email is None:
        form.get('email')


    # Verify if email exists in User Service
    user_service_url = f"{USER_SERVICE_URL}/user/{email}"
    user_response = requests.get(user_service_url)

    if user_response.status_code == 200:
        # Generate a password reset token with a short expiration (e.g., 15 minutes)
        reset_payload = {'email': email, 'exp': time.time() + 900} 
        reset_token = create_jwt(reset_payload, private_key)

        # Send reset email
        if send_reset_email(email, reset_token):
            # return jsonify({'message': 'Password reset email sent'}), 200
            return redirect('https://isa-facade.azurewebsites.net/message?message="Reset email sent successfully"', code=304)

        # return jsonify({'message': 'Failed to send email'}), 500
        return redirect('https://isa-facade.azurewebsites.net/message?message="Something went wrong"', code=304)


    return jsonify({'message': 'Email not found'}), 404

# Helper function to send a password reset email
def send_reset_email(recipient_email, reset_token):
    base_reset_url = 'http://isa-facade.azurewebsites.net/reset-password'
    
    reset_url = base_reset_url + "?jwt=" + reset_token
    subject = "Password Reset Request"
    body = f"Hello {recipient_email}, \nClick the link below to reset your password:\n\n{reset_url}"

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDGRID_USERNAME, SENDGRID_API_KEY)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

# Protected route example
@app.route('/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        # return jsonify({'message': 'Token is missing'}), 401
        return redirect('https://isa-facade.azurewebsites.net/message?message="You need to login to see this page"', code=304)


    token = auth_header.split(' ')[1]

    # Load the public key (for debugging)
    if public_key is None:
        with open('public.pem', 'r') as f:
            public_key = f.read()

    try:
        # Decode and verify the JWT token
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return jsonify({'message': 'Access granted', 'payload': payload})
    except jwt.ExpiredSignatureError:
        # return jsonify({'message': 'Token has expired'}), 401
        return redirect('https://isa-facade.azurewebsites.net/message?message="Login again, session expired"', code=304)

    except jwt.InvalidTokenError:
        # return jsonify({'message': 'Invalid token'}), 401
        return redirect('https://isa-facade.azurewebsites.net/message?message="Your token is invalid"', code=304)


if __name__ == '__main__':
    app.run(port=5000)
