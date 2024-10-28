###MAKE SURE TO ACTIVATE VENV FIRST
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import jwt
import time
import os

public_key = None
private_key = None

# try:
#     public_key = os.environ.get('PUBLIC_KEY')
#     private_key = os.environ.get('PRIVATE_KEY')
# except:
#     pass

# if public_key is None or private_key is None:
#     raise RuntimeError("Missing environment variables for keys")

if private_key is None:
    #Load the private key from the private.pem file
    with open('private.pem', 'r') as f:
        private_key = f.read()


app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}}) 
# CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}}) 


# Utility function to create a JWT token using RS256
def create_jwt(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='RS256')

# Mock user database (for demonstration purposes)
users = {
    "admin": "password"
}
# this login method only supports token in header, other one also sets http only cookie
# @app.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')

#     # Check if user exists and password is correct
#     if username in users and users[username] == password:
#         # Create JWT token with expiration (e.g., 1 hour)
#         payload = {
#             'username': username,
#             'exp': time.time() + 3600  # 1 hour expiration
#         }
#         token = create_jwt(payload, private_key)
#         # response.set_cookie('jwt', token, httponly=True, secure=False, samesite='Lax')  # Set Secure=True in production
        

#         return jsonify({'token': token})

#     return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/login', methods=['POST'])
def login():
    print("login process begins")
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Check if user exists and password is correct
    if username in users and users[username] == password:
        # Create JWT token with expiration (e.g., 1 hour)
        payload = {
            'username': username,
            'exp': time.time() + 3600  # Token expires in 1 hour
        }
        print("private key: ", private_key)
        token = create_jwt(payload, private_key)

        # Create a response object
        response = make_response(jsonify({'token': token}))  # JSON response still includes the token

        response.headers['credentials'] = 'include'

        # Set the JWT as an HTTP-only, secure cookie
        response.set_cookie('jwt', token, httponly=True, secure=False, samesite='Lax')  # Set Secure=True in production

        return response  # Return the response with both JSON and the cookie

    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
def protected():
    # Extract token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        # debug_output = f"{private_key}"
        return jsonify({'message': 'Token is missing'}), 401

    token = auth_header.split(' ')[1]

    
    # Load the public key (optional verification for debugging purposes)
    if public_key is None:
        with open('public.pem', 'r') as f:
            public_key = f.read()


    try:
        # Decode and verify the JWT token
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return jsonify({'message': 'Access granted', 'payload': payload})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run()
