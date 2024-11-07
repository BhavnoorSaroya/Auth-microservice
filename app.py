from flask import Flask, request, jsonify, make_response, redirect
from flask_cors import CORS
import jwt
import time
import os
import requests
from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
# Load the private key for signing tokens
private_key = None
public_key = None



if private_key is None:
    with open('private.pem', 'r') as f:
        private_key = f.read()
if public_key is None:
    with open('public.pem', 'r') as f:
        public_key = f.read()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration for the User Service and email
# FRONTEND_URL = 'http://localhost:3000'
FRONTEND_URL = 'https://isa-singh.azurewebsites.net'
# USER_SERVICE_URL = 'http://localhost:5001'
USER_SERVICE_URL = 'https://isa-database-microservice.onrender.com'
SENDGRID_USERNAME = 'apikey'  # Use 'apikey' as the username for SendGrid SMTP
EMAIL_SENDER = 'overlord@saroya.dev'  # Set your email
SMTP_SERVER = 'smtp.sendgrid.net'  # Replace with your SMTP server
SMTP_PORT = 587
with open('api.key', 'r') as f:
        SENDGRID_API_KEY = f.read().strip()
EMAIL_PASSWORD = SENDGRID_API_KEY
SIGNATURE_KEY = serialization.load_pem_public_key(public_key.encode('utf-8'))
SIGNER_KEY = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)# Utility function to create a JWT token using RS256
def create_jwt(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='RS256')

def create_signature(payload, private_key):
    # Create a new SHA-256 hash of the payload
    h = payload.encode('utf-8')
    
    # Create a signer with the private key
    # signer = PKCS1_v1_5.new(private_key)
    signature = private_key.sign(
         h, 
            padding.PKCS1v15(),
            hashes.SHA256()
    )
    
    # Sign the payload
    # signature = signer.sign(h)
    
    # Return the base64-encoded signature
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(payload, signature):
    # return True # For now, always return True to bypass signature verification
    """
    Verifies the signature of the given payload using the public key.

    :param payload: The original payload as a string.
    :param signature: The signature to verify, base64-encoded.
    :return: True if the signature is valid, False otherwise.
    """
    try:
        # Create a new SHA-256 hash of the payload
        # h = SHA256.new(payload.encode('utf-8'))
        
        # Decode the base64-encoded signature
        decoded_signature = base64.b64decode(signature)
        
        # Create a verifier with the public key
        # verifier = PKCS1_v1_5.new(public_key)

        SIGNATURE_KEY.verify(
            decoded_signature,
            payload.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Verify the signature
        print("Signature verified")
        return True  # verifier.verify(h, decoded_signature)
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Alternatively, for the entire app, add a global options handler
@app.before_request
def before_request():
    # response.headers['Access-Control-Allow-Origin'] = 'https://isa-singh.azurewebsites.net'
    # response.headers['Access-Control-Allow-Origin'] = 'localhost:8080'
    if request.method == 'OPTIONS':
        response = jsonify({"message": "Preflight OK"})
        response.headers['Access-Control-Allow-Origin'] = 'https://isa-singh.azurewebsites.net'
        # response.headers['Access-Control-Allow-Origin'] = 'localhost:8080'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.status_code = 200
        return response
    signature_header = request.headers.get('x-gateway-signature')
    if signature_header is None:
        return jsonify({'message': 'Invalid request, needs to be signed'}), 401
    
    # Extract the payload (in this example, we use the raw request data)
    # Adjust this as needed to match how the payload is constructed on your side
    # payload = request.method + request.url + request.data.decode('utf-8')
    payload = request.method + request.path
    # print("url", request.url)
    # print("payload", payload)


    # Verify the signature
    if verify_signature(payload, signature_header):
        pass  # Continue processing the request

    else:
        return jsonify({'message': 'Invalid signature'}), 403

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')


    # Verify user with the User Service
    user_service_url = f"{USER_SERVICE_URL}/login"
    
    
    # print("signature", signature)
    response = requests.post(
        user_service_url, 
        json={'email': email, 'password': password}, 
        headers={'x-gateway-signature': create_signature(request.method + request.path, SIGNER_KEY)}
        )

    if response.status_code == 200:
        # Generate JWT token on successful authentication
        payload = {'email': email, 'exp': time.time() + 3600}
        token = create_jwt(payload, private_key)
        
        # Set token in HTTP-only cookie
        response = make_response(jsonify({'token': token}))
        # response.headers['Access-Control-Allow-origin'] = 'https://isa-singh.azurewebsites.net'
        response.set_cookie(
            'jwt', token, httponly=True, secure=True, samesite='None'
        )
        return response
    return jsonify({'message': 'Invalid credentials'}), 401

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    data = request.json 
    email = data.get('email')
    password = data.get('password')

    user_service_url = f"{USER_SERVICE_URL}/register"
    response = requests.post(
        user_service_url, 
        json={'email': email, 'password': password}, 
        headers={'x-gateway-signature': create_signature(request.method + request.path, SIGNER_KEY)}
        )

    print(response.status_code)
    if response.status_code == 201:
        print("Registered Successfully")
        # return redirect(f'{user_service_url}/message?message="Registered Successfully"', code=200)
        return jsonify(response.json()), response.status_code
    # print(response, "status code \n\n" , response.status_code)
    print("Failed to register")
    return jsonify(response.json()), response.status_code

# Route to send a password reset email
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
        email = request.form.get('email')
        # email = data.get('email')
    else:
        data = request.json
        email = data.get('email') 
    if email is None:
        return jsonify({'message': 'something went wrong'}), 404

    


    # Verify if email exists in User Service
    user_service_url = f"{USER_SERVICE_URL}/user/{email}"
    user_response = requests.get(
        user_service_url, 
        headers={'x-gateway-signature': create_signature(request.method + request.path, SIGNER_KEY)}
        )

    if user_response.status_code == 200:
        # Generate a password reset token with a short expiration (e.g., 15 minutes)
        reset_payload = {'email': email, 'exp': time.time() + 900} 
        reset_token = create_jwt(reset_payload, private_key)

        # Send reset email
        if send_reset_email(email, reset_token):
            # return jsonify({'message': 'Password reset email sent'}), 200
            print("Email sent successfully")
            return redirect(f'{FRONTEND_URL}/message?message=Reset email sent successfully&anchor=Go to login&link=/login', code=302)

        # return jsonify({'message': 'Failed to send email'}), 500
        print("Failed to send email")
        return redirect(f'{FRONTEND_URL}/message?message="Something went wrong"', code=302)


    return redirect(f'{FRONTEND_URL}/message?message="User not found"', code=302)
    

# Helper function to send a password reset email
def send_reset_email(recipient_email, reset_token):
    
    base_reset_url = f'{FRONTEND_URL}/password-reset'
    
    reset_url = base_reset_url + "?jwt=" + reset_token
    subject = "Password Reset Request"
    body = f"Hello {recipient_email}, \nClick the link below to reset your password:\n\n{reset_url}"
    
    # print("\n", reset_token, "\n")

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
        # for testing we say it worked

# Protected route example
@app.route('/protected', methods=['GET'])
def protected():
    return jsonify({'message': 'Access granted(test route)'})

    # auth_header = request.headers.get('Authorization')
    # # if not auth_header or not auth_header.startswith('Bearer '):
    # #     # return jsonify({'message': 'Token is missing'}), 401
    #     # return redirect('https://isa-facade.azurewebsites.net/message?message="You need to login to see this page"', code=304)


    # token = auth_header.split(' ')[1]

    # # Load the public key (for debugging)
    # if public_key is None:
    #     with open('public.pem', 'r') as f:
    #         public_key = f.read()

    # try:
    #     # Decode and verify the JWT token
    #     payload = jwt.decode(token, public_key, algorithms=['RS256'])
    #     return jsonify({'message': 'Access granted', 'payload': payload})
    # except jwt.ExpiredSignatureError:
    #     # return jsonify({'message': 'Token has expired'}), 401
    #     return redirect('https://isa-facade.azurewebsites.net/message?message="Login again, session expired"', code=304)

    # except jwt.InvalidTokenError:
    #     # return jsonify({'message': 'Invalid token'}), 401
    #     return redirect('https://isa-facade.azurewebsites.net/message?message="Your token is invalid"', code=304)


if __name__ == '__main__':
    app.run(port=8000)
