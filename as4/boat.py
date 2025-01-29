from flask import Blueprint, request, Flask, jsonify, make_response
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('boat', __name__, url_prefix='/boats/')

@bp.route('', methods=['POST','GET'])
def boats_get_post():

    if request.method == 'POST':
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        try:
            new_boat.update({'name': content['name'], 'type': content['type'], 'length': content['length'], 'loads': []})
        except:
            return make_response(jsonify(Error="The request object is missing at least one of the required attributes"), 400)
        client.put(new_boat)

        #create id element to be dumped to json, tried putting in .update but 'id' was being set to None
        new_boat['id'] = str(new_boat.key.id)
        #On the fly self link creation
        new_boat['self'] = request.base_url + str(new_boat.key.id)
        return (json.dumps(new_boat), 201)
  
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        q_limit = int(request.args.get('limit', '3'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            '''Add self link'''
            e["self"] = request.base_url + str(e.key.id)
        output = {"boats": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    
    else:
        return 'Method not recogonized'

@bp.route('/<id>', methods=['GET', 'PUT','DELETE'])
def boats_put_delete(id):

    if request.method == 'GET':
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat == None:
            return make_response(jsonify(Error="No boat with this boat_id exists"), 404)
        #On the fly self link creation
        boat['id'] = int(id)
        boat['self'] = request.base_url + str(boat.key.id)
        return (boat, 200)

    elif request.method == 'PUT':
        content = request.get_json()
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        boat.update({'name': content['name'], 'type': content['type'], 'length': content['length']})
        client.put(boat)
        return ('',200)
    
    elif request.method == 'DELETE':
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat == None:
            return make_response(jsonify(Error="No boat with this boat_id exists"), 404)        
        '''Unloading boat loads before boat deletion'''

        for l in boat['loads']:
            del l['carrier']

        client.delete(boat_key)
        return ('',204)
    
    else:
        return 'Method not recogonized'

@bp.route('/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_delete_load(bid,lid):

    if request.method == 'PUT':
        boat_key = client.key(constants.boats, int(bid))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(lid))
        load = client.get(key=load_key)
        if boat == None or load == None:
            return make_response(jsonify(Error="The specified boat and/or load does not exist"), 404)

        if load["carrier"] != None:
            return make_response(jsonify(Error="The load is already loaded on another boat"), 403)

        if 'loads' in boat.keys():

            ''' Add carrier to load '''
            load['carrier'] = {"id": str(boat.id), "name": boat["name"], "self": request.base_url + str(boat.id)}
            boat['loads'].append(load)

        else:

            ''' Add carrier to load '''
            load['carrier'] = {"id": str(boat.id), "name": boat["name"], "self": request.base_url + str(boat.id)}
            boat['loads'] = [load.id]

            
        client.put(load)
        client.put(boat)
        '''not sure if this is correct way to save changes to the load '''
        #client.put(load)
        return('',204)
    
    if request.method == 'DELETE':
        boat_key = client.key(constants.boats, int(bid))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(lid))
        load = client.get(key=load_key)
        if boat == None or load == None:
            return make_response(jsonify(Error="The specified boat and/or load does not exist"), 404)
        if 'loads' in boat.keys():
            boat['loads'].remove(int(lid))
            ''' Remove carrier from load '''
            load['carrier'] = {}
            client.put(load)
            client.put(boat)
            '''not sure if this is correct way to save changes to the load '''
            client.put(load)
        return('',200)

@bp.route('/<id>/loads', methods=['GET'])
def get_loads(id):

    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    if boat == None:
            return make_response(jsonify(Error="No boat with this boat_id exists"), 404)

    load_list  = []

    if 'loads' in boat.keys():
        for lid in boat['loads']:
            load_key = client.key(constants.loads, int(lid))
            load_list.append(load_key)
        return json.dumps(client.get_multi(load_list))
    
    else:
        return json.dumps([])
