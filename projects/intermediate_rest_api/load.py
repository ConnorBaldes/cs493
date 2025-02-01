from flask import Blueprint, request, Flask, jsonify, make_response
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('load', __name__, url_prefix='/loads/')

@bp.route('', methods=['POST','GET'])
def loads_get_post():

    if request.method == 'POST':
        content = request.get_json()
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        try:
            new_load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"], "carrier": None})
        except:
            return make_response(jsonify(Error="The request object is missing at least one of the required attributes"), 400)
        client.put(new_load)
        new_load['id'] = new_load.key.id
        new_load['self'] = request.base_url + str(new_load.key.id)
        return (new_load, 201)
    
    elif request.method == 'GET':
        query = client.query(kind=constants.loads)
        q_limit = int(request.args.get('limit', '2'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))
        
        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)


@bp.route('/<id>', methods=['GET', 'PUT','DELETE'])
def loads_put_delete(id):

    if request.method == 'GET':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load == None:
            return make_response(jsonify(Error="No load with this load_id exists"), 404)
        #On the fly self link creation
        load['id'] = int(id)
        load['self'] = request.base_url + str(load.key.id)
        return (load, 200)
    
    elif request.method == 'PUT':
        content = request.get_json()
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"]})
        client.put(load)
        return ('',200)
    
    elif request.method == 'DELETE':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load == None:
            return make_response(jsonify(Error="No load with this load_id exists"), 404)
        client.delete(load)
        return ('',204)
    
    else:
        return 'Method not recogonized'