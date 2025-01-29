
from flask import Flask, request, redirect, url_for, jsonify, make_response, Blueprint, abort, render_template
from google.cloud import datastore
import json
from json2html import *
import constants

client = datastore.Client()
bp = Blueprint('boat', __name__, url_prefix='/boats')

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
        raise InvalidAPIUsage("Bad Request", status_code=400)

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
            raise InvalidAPIUsage("Bad Request", status_code=400)
        
    if content.get('name') != None:
        name_is_string = isinstance(content['name'], str)
        if not name_is_string:
            raise InvalidAPIUsage("Bad Request", status_code=400)
        # TO DO: What if the the string is outrageously long or contains special characters?

        '''
        Need to check if the client is trying to change the name, 
        if so we need to query the boats list to ensure no boats with 
        duplicate names are created
        '''
        query = client.query(kind=constants.boats)
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
            raise InvalidAPIUsage("Bad Request", status_code=400)
        
    if content.get('length') != None:
        length_is_int = isinstance(content['length'], int)
        if not length_is_int:
            raise InvalidAPIUsage("Bad Request", status_code=400)
        
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

        '''
        if json not acceptable respond with HTML
        json2html is used to convert the json boat object
        to an html acceptable form. status code, also check
        for a redirrect status code(303) in which case the 'location'
        must be set in the header
        '''

    elif 'text/html' in request.accept_mimetypes:     
        response = make_response(json2html.convert(json = json.dumps(content)))
        response.mimetype = 'text/html'
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


@bp.errorhandler(InvalidAPIUsage)
def invalid_api_usage(e):
     return jsonify(e.to_dict()), e.status_code


@bp.route('', methods=['POST','GET', 'PUT', 'PATCH', 'DELETE'])
def boats_get_post():

    if request.method == 'POST':

        # POST request contains client input that must be verified
        # as valid content
        content = check_input(request)

        # New boat entity is created, its content is updated and it is 
        # added to the datastore boats list
        with client.transaction():
            new_boat_key = client.key(constants.boats)
            new_boat = datastore.Entity(key=new_boat_key)

            new_boat.update(content)
            client.put(new_boat)

       
        # The id and self link are added to the new_boat entity before 
        # returning so user can access them if desired.
        new_boat['id'] = new_boat.key.id
        new_boat['self'] = request.base_url + '/' + str(new_boat.key.id)

        response = build_response(request, new_boat, 201)
        return response

    else:
        raise InvalidAPIUsage("Method Not Allowed", status_code=405)
    


    
@bp.route('/<id>', methods=['POST','GET', 'PUT', 'PATCH', 'DELETE'])
def get_put_patch_delete_boats(id):

    if request.method == 'GET':

        
        # Getting the boat key from the provided boat id then retrieving
        # the desired boat entity and checking that boat is valid.      
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(boat_key)
        if boat is None:
            raise InvalidAPIUsage("Not Found", status_code=404)
        
        # The id and self link are added to the boat entity before 
        # returning so user can access them if desired.
        boat['id'] = boat.key.id
        boat['self'] = request.base_url

        response = build_response(request, boat, 201)
        return response
        
    elif request.method == 'PUT':

        # PUT request contains client input that must be verified
        # as valid content
        content = check_input(request)

        '''
        Getting the boat key from the provided boat id then retrieving
        the desired boat entity and checking that boat is valid.
        '''   
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(boat_key)
        if boat is None:
            raise InvalidAPIUsage("Not Found", status_code=404)
        
        # Sending 303 for PUT response
        boat.update(content)
        client.put(boat)
        # The id and self link are added to the boat entity before 
        # returning so user can access them if desired.
        boat['id'] = boat.key.id
        boat['self'] = request.base_url
        response = build_response(request, boat, 303)
        response.headers['location'] = request.base_url
        return response
        

    elif request.method == 'PATCH':

        # PATCH request contains client input that must be verified
        # as valid content
        content = check_input(request)

        '''
        Getting the boat key from the provided boat id then retrieving
        the desired boat entity and checking that boat is valid.
        '''     
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(boat_key)
        if boat is None:
            raise InvalidAPIUsage("Not Found", status_code=404)
        
        '''
        Patch requires that a client be allowed to provide individual keys
        in their request body that they would like changed in the boat 
        that they are accessing. Therefore each key that the client can 
        change must be checked for in the client provided content, and 
        if found must replace the current value in the desired boat entity.
        '''
        with client.transaction():

            if content.get('name') != None:
                boat['name'] = content['name']

            if content.get('type') != None:
                boat['type'] = content['type']

            if content.get('length') != None:
                boat['length'] = content['length']
            client.put(boat)
        
        # The id and self link are added to the boat entity before 
        # returning so user can access them if desired.
        boat['id'] = boat.key.id
        boat['self'] = request.base_url
        response = build_response(request, boat, 200)
        return response

    elif request.method == 'DELETE':

        '''
        Getting the boat key from the provided boat id then retrieving
        the desired boat entity and checking that boat is valid.
        '''      
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(boat_key)
        if boat is None:
            raise InvalidAPIUsage("Not Found", status_code=404)
        
        client.delete(boat)
        response = build_response(request, "Boat Deleted", 204)
        return response
    
    else:
        raise InvalidAPIUsage("Method Not Allowed", status_code=405)