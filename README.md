# auth microservice 

This auth microservice is implemented in flask and uses asymmetric encryption 

For obvious reasons I have not provided my keys, however, to run the service, you can setup your own python venv and generate your own keys easily

## Setup on linux: 
### note that if you are on windows, you can use wsl or adapt the instructions for windows
1. ```python3 -m venv myenv``` #this will create a virtual environment
2. ```source myenv/bin/activate``` #this will activate the venv
3. ```$ pip install -r requirements.txt``` install the necessary packages

### generate the keys with openssl
1. ```openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048```
2. ```openssl rsa -pubout -in private.pem -out public.pem```

### run the project 
1. ```flask run```