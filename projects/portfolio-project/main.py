from google.cloud import datastore
from flask import Flask, request, jsonify, make_response
from six.moves.urllib.request import urlopen
from authlib.integrations.flask_client import OAuth
from jose import jwt
from json2html import *
import requests
import json

app = Flask(__name__)


app.secret_key = ""

client = datastore.Client()
users = "users"
boats = "boats"
loads = "loads"

CLIENT_ID = ""
CLIENT_SECRET = ""
DOMAIN = "dev-ogyc14zyj0e06od5.us.auth0.com"
ALGORITHMS = ["RS256"]

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

'''
check_input: This is where incoming content from a user 
is checked to ensure that it is complete, of the right type,
and the value of each key is reasonable.
'''
def check_input(request):

    # Ensure that the content-type the user provided is JSON
    if 'application/json' not in request.content_type:
        raise InvalidAPIUsage("Unsupported Media Type", status_code=415)
    try:
        content = request.get_json()
    except:
        raise InvalidAPIUsage("Bad request.get_json()", status_code=400)

    '''
    Both 'POST' AND 'PUT' require a full content field
    with the name, type, and length they want to input in 
    the new or existing boat. This is a not so elegant way 
    of checking that by trying to accces each of the required
    keys and then catching a json key error if accessing a 
    certain key fails. A 406 error is then raised and a message
    is sent to the user that they are missing required content.
    '''
    if request.method == 'POST' or request.method == 'PUT':
        try:
            content['name']
            content['type']
            content['length']
        except KeyError as error:
            raise InvalidAPIUsage("No name, type, or length", status_code=400)
        
    if content.get('name') != None:
        name_is_string = isinstance(content['name'], str)
        if not name_is_string:
            raise InvalidAPIUsage("Bad name", status_code=400)
        # TO DO: What if the the string is outrageously long or contains special characters?

        '''
        Need to check if the client is trying to change the name, 
        if so we need to query the boats list to ensure no boats with 
        duplicate names are created
        '''
        query = client.query(kind=boats)
        query.add_filter('name', '=', content['name'])
        results = list(query.fetch())
        if results:
            raise InvalidAPIUsage("Forbidden", status_code=403)
        
    '''
    check for the other keys the client can change, if they are present
    check that their values are of the correct type.
    'type' is the boat type and should be a string
    'length' is the boat length and should be an integer
    '''  
    if content.get('type') != None:
        type_is_string = isinstance(content['type'], str)
        if not type_is_string:
            raise InvalidAPIUsage("Bad type", status_code=400)
        
    if content.get('length') != None:
        length_is_int = isinstance(content['length'], int)
        if not length_is_int:
            raise InvalidAPIUsage("Bad length", status_code=400)
        
    return content

def build_response(request, content, status_code):
        
    '''
    check first if the user will accept a JSON response
    if so send boat json object with json mimetype and 
    status code, also check for a redirrect status code(303) 
    in which case the 'location' must be set in the header
    '''
    if 'application/json' in request.accept_mimetypes:
        response = make_response(json.dumps(content))
        response.mimetype = 'application/json'
        response.status_code = status_code
        return response
        
    else:
        raise InvalidAPIUsage("Not Acceptable", status_code=406)

'''
InvalidAPIUsage is a class that I found on the 'Handling Application Errors'
page of the flask documentation.  
URL: https://flask.palletsprojects.com/en/3.0.x/errorhandling/#blueprint-error-handlers    
'''
class InvalidAPIUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        super().__init__()
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['Error'] = self.message
        return rv


@app.errorhandler(InvalidAPIUsage)
def invalid_api_usage(e):
     return jsonify(e.to_dict()), e.status_code

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def decode_token(token):
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /boats to use this API"

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload   


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    #create request
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    
    #decode JWT
    response_data = json.loads(r.text)
    id_token = response_data.get('id_token')
    decoded_token = decode_token(id_token)
    
    #Look for existing user with id as JWT 'sub'
    query = client.query(kind=users)
    query.add_filter('id', '=', decoded_token['sub'])
    results = list(query.fetch())
    
    #if user exists return ID and token, if not create user and return ID and token
    if results:
        user_content = {}
        user_content['id'] = decoded_token['sub']
        user_content['id_token'] = id_token
        response = build_response(request, user_content, 200)
        return response
    else:
        with client.transaction():
            new_user_key = client.key(users)
            new_user = datastore.Entity(key=new_user_key)
            new_user['id'] = decoded_token['sub']
            new_user['id_token'] = id_token
            client.put(new_user)
            response = build_response(request, new_user, 201)
            return response
        

@app.route('/users', methods=['GET'])
def get_users():

    if request.method == 'GET':
        query = client.query(kind=users)
        results = list(query.fetch())
        response = build_response(request, results, 200)
        return response
    else:
        return {"Error": "Method Not Allowed"}, 405


# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET'])
def boats_post():
    if request.method == 'POST':

        try:
            payload = verify_jwt(request)
            content = request.get_json()
            new_boat = datastore.entity.Entity(key=client.key(boats))
            new_boat.update({"name": content["name"], "type": content["type"],
            "length": content["length"], "loads": [], "owner": payload.get('sub')})
            client.put(new_boat)
            new_boat["id"] = new_boat.key.id
            new_boat['self'] = request.base_url + '/' + str(new_boat.key.id)
            client.put(new_boat)
            response = build_response(request, new_boat, 201)
            return response
        except Exception as e:
            return {"Error": "Invalid JWT"}, 403
    
    elif request.method == 'GET':
    
        try:
            payload = verify_jwt(request)
            query = client.query(kind=boats)
            query.add_filter("owner", "=", payload.get('sub'))
            results = list(query.fetch())
            response = build_response(request, results, 200)
            return response
        except Exception as e:
            return {"Error": "Invalid JWT"}, 403    


    else:
        return {"Error": "Method Not Allowed"}, 405

@app.route('/boats/<bid>/loads/<lid>', methods=['PATCH', 'DELETE'])
def load_unload_boat(bid, lid):

    if request.method == 'PATCH':

        try:
            payload = verify_jwt(request)
        except AuthError as e:
            return json.dumps({"error": e.error}), e.status_code, {'Content-Type': 'application/json'}  

        boat_key = client.key(boats, int(bid))
        boat = client.get(boat_key)  
        if boat is None:
            return {"Error": "Boat not Found"}, 404
        else:
            if boat['owner'] == payload.get('sub'):
                
                load_key = client.key(loads, int(lid))
                load = client.get(load_key)   
                if not load:
                    raise AuthError({"code": "invalid_load", "description": "Invalid load"}, 400)
                if load.get('boat_id'):
                    raise AuthError({"code": "already_loaded", "description": "Load is already loaded on a boat"}, 400)
                
                boat['loads'].append(load)
                load['boat_id'] = bid

                with client.transaction():
                    client.put(boat)
                    client.put(load)

                return jsonify({"message": "Load successfully added to the boat"}), 200

            else:
                return {"Error": "Wrong JWT"}, 403
            
    if request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
        except AuthError as e:
            return json.dumps({"error": e.error}), e.status_code, {'Content-Type': 'application/json'}

        boat_key = client.key(boats, int(bid))
        boat = client.get(boat_key)
        if boat is None:
            return {"Error": "Boat not Found"}, 404
        else:
            if boat['owner'] == payload.get('sub'):
                        
                load_key = client.key(loads, int(lid))
                load = client.get(load_key)   
                if not load:
                    raise AuthError({"code": "invalid_load", "description": "Invalid load"}, 400)
                        
                # Check if the load is loaded on the specified boat
                if load.get('boat_id') == bid:
                    # Unload the boat by removing the load from the boat's loads list
                    boat['loads'].remove(load)
                    # Update the load entity to indicate it's no longer on a boat
                    load['boat_id'] = None

                    with client.transaction():
                        client.put(boat)
                        client.put(load)

                    return jsonify({"message": "Load successfully unloaded from the boat"}), 200
                else:
                    return {"Error": "Load is not loaded on the specified boat"}, 403


            else:
                return {"Error": "Wrong JWT"}, 403
    else:
        return {"Error": "Method Not Allowed"}, 405

            
@app.route('/boats/<boat_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def update_boat(boat_id):

    if request.method == 'GET':
        try:
            payload = verify_jwt(request)
            boat_key = client.key(boats, int(boat_id))
            boat = client.get(boat_key)  
            if boat is None:
                return {"Error": "Boat not Found"}, 404
            else:
                if boat['owner'] == payload.get('sub'):
                    response = build_response(request, boat, 200)
                    return response
                else:
                    return {"Error": "Wrong JWT"}, 403

        except Exception as e:
            return {"Error": "Invalid JWT"}, 401
        
    elif request.method == 'PATCH':
        try:
            payload = verify_jwt(request)
            content = request.get_json()
            boat_key = client.key(boats, int(boat_id))
            boat = client.get(boat_key)  
            if boat is None:
                return {"Error": "Boat not Found"}, 404
            else:
                if boat['owner'] == payload.get('sub'):
                    with client.transaction():

                        if content.get('name') != None:
                            boat['name'] = content['name']

                        if content.get('type') != None:
                            boat['type'] = content['type']

                        if content.get('length') != None:
                            boat['length'] = content['length']

                        client.put(boat)
                response = build_response(request, boat, 200)
                return response
            
        except Exception as e:
            return {"Error": "Invalid JWT"}, 401
            
    elif request.method == 'PUT':
        try:
            payload = verify_jwt(request)
            content = request.get_json()
            boat_key = client.key(boats, int(boat_id))
            boat = client.get(boat_key)  
            if boat is None:
                return {"Error": "Boat not Found"}, 403
            else:
                if boat['owner'] == payload.get('sub'):
                    with client.transaction():

                        boat.update(content)
                        client.put(boat)

                response = build_response(request, boat, 303)
                response.headers['location'] = request.base_url
                return response
            
        except Exception as e:
            return {"Error": "Invalid JWT"}, 401
        
    elif request.method == 'DELETE':


        payload = verify_jwt(request)
        boat_key = client.key(boats, int(boat_id))
        boat = client.get(boat_key)  
        if boat is None:
            return {"Error": "Boat not Found"}, 404
        else:
            if boat['owner'] == payload.get('sub'):
                # Set boat_id to None for each load associated with the boat
                if 'loads' in boat:
                    for load in boat['loads']:
                        
                        if load:
                            load['boat_id'] = None
                            client.put(load)

                client.delete(boat)
                return "Boat Deleted", 204
            else:
                return {"Error": "Wrong JWT"}, 403
    
    else:
        return {"Error": "Method Not Allowed"}, 405

        
@app.route('/loads', methods=['POST', 'GET'])
def loads_post():
    if request.method == 'POST':

        content = request.get_json()
        new_load = datastore.entity.Entity(key=client.key(loads))
        new_load.update({"contents": content["contents"], "boat_id": None,
        "load_date": None, "unload_date": None})
        client.put(new_load)
        new_load["id"] = new_load.key.id
        new_load['self'] = request.base_url + '/' + str(new_load.key.id)
        client.put(new_load)
        response = build_response(request, new_load, 201)
        return response

    
    elif request.method == 'GET':

        query = client.query(kind=loads)
        results = list(query.fetch())
        return json.dumps(results), 200
    
    else:
        return {"Error": "Method Not Allowed"}, 405


@app.route('/loads/<load_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def update_load(load_id):

    if request.method == 'GET':


            load_key = client.key(loads, int(load_id))
            load = client.get(load_key)  
            if load is None:
                return {"Error": "Load not found"}, 404
            else:
                response = build_response(request, load, 200)
                return response


        
    elif request.method == 'PATCH':


        content = request.get_json()
        load_key = client.key(loads, int(load_id))
        load = client.get(load_key)  
        if load is None:
            return {"Error": "Load not found"}, 404
        else:
            with client.transaction():

                if content.get('contents') != None:
                    load['contents'] = content['contents']

                if content.get('boat_id') != None:
                    load['boat_id'] = content['boat_id']

                if content.get('load_date') != None:
                    load['load_date'] = content['load_date']

                if content.get('unload_date') != None:
                    load['unload_date'] = content['unload_date']

                client.put(load)
            response = build_response(request, load, 200)
            return response
 
            
    elif request.method == 'PUT':

        content = request.get_json()
        load_key = client.key(loads, int(load_id))
        load = client.get(load_key)  
        if load is None:
            return {"Error": "Boat not found"}, 404
        else:

            with client.transaction():

                load.update(content)
                client.put(load)

        response = build_response(request, load, 303)
        response.headers['location'] = request.base_url
        return response

        
    elif request.method == 'DELETE':


        load_key = client.key(loads, int(load_id))
        load = client.get(load_key)  
        if load is None:
            return {"Error": "Load not found"}, 404
        else:
            if load.get('boat_id'):
                boat_key = client.key(boats, int(load['boat_id']))
                boat = client.get(boat_key)

                # Remove the load from the boat's loads list
                if boat and load in boat['loads']:
                    boat['loads'].remove(load)
                    client.put(boat)
            client.delete(load)
            return "Load Deleted", 204

    else:
        return {"Error": "Method Not Allowed"}, 405


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)