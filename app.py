import datetime
from time import mktime

from flask import Flask, request, jsonify, make_response
import jwt
import requests

from secrets import api_auth_token, jwt_secret_key
from utils import parse_date_time
from business import get_user_by_email

app = Flask(__name__)


def decode_auth_token(auth_token):
    # use jwt, jwt_secret_key
    # should be a one liner, but we want you to see how JWTs work
    decoded_token = jwt.decode(auth_token, jwt_secret_key, algorithms=['HS512'])
    return decoded_token

def encode_auth_token(user_id, name, email, scopes):
    # use jwt and jwt_secret_key imported above, and the payload defined below
    # should be a one liner, but we want you to see how JWTs work
    # remember to convert the result of jwt.encode to a string
    # make sure to use .decode("utf-8") rather than str() for this
    try: 
        payload = {
            'sub': user_id,
            'name': name,
            'email': email,
            'scope': scopes,
            'exp': mktime((datetime.datetime.now() + datetime.timedelta(days=1)).timetuple())
        }
        token = jwt.encode(payload, jwt_secret_key, algorithm='HS512').decode("utf-8")
        return token
    except Exception as e:
        return e


def get_user_from_token():
    # use decode_auth_token above and flask.request imported above
    # should pull token from the Authorization header
    # Authorization: Bearer {token}
    # Where {token} is the token created by the login route
    auth_header = request.headers.get('Authorization', None)
    if not auth_header: return
    token = auth_header.split(" ")[1]
    payload = decode_auth_token(token)
    return payload


@app.route('/')
def status():
    return 'API Is Up'


@app.route('/user', methods=['GET'])
def user():
    # get the user data from the auth/header/jwt
    user_data = get_user_from_token()
    user_id = user_data['sub']
    user_name = user_data['name']
    user_email = user_data['email']
    response_obj = {
        'user_id': user_id,
        'name': user_name,
        'email': user_email
    }
    return make_response(jsonify(response_obj))


@app.route('/login', methods=['POST'])
def login():
    # use use flask.request to get the json body and get the email and scopes property
    # use the get_user_by_email function to get the user data
    # return a the encoded json web token as a token property on the json response as in the format below
    # we're not actually validitating a password or anything because that would add unneeded complexity
    try:
        json_body = request.get_json()
        user_email = json_body.get("email")
        scopes = json_body.get("scope")
    except KeyError:
        return {"Message": "One or more fields are empty"}
    user_data = get_user_by_email(user_email)
    user_id = user_data['id']
    user_name = user_data['name']
    auth_token = encode_auth_token(user_id, user_name, user_email, scopes)
    response_obj = {'token': auth_token}
    return make_response(jsonify(response_obj))



@app.route('/widgets', methods=['GET'])
def widgets():
    # accept the following optional query parameters (using the the flask.request object to get the query params)
    # type, created_start, created_end
    # dates will be in iso format (2019-01-04T16:41:24+0200)
    # dates can be parsed using the parse_date_time function written and imported for you above
    # get the user ID from the auth/header
    # verify that the token has the widgets scope in the list of scopes

    # Using the requests library imported above send the following the following request,

    # GET https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}
    # HEADERS
    # Authorization: apiKey {api_auth_token}

    # the api will return the data in the following format

    # [ { "id": 1, "type": "floogle", "created": "2019-01-04T16:41:24+0200" } ]
    # dates can again be parsed using the parse_date_time function

    # filter the results by the query parameters
    # return the data in the format below
    query_params = request.args
    user_data = get_user_from_token()
    user_id = user_data['sub']
    scopes = user_data['scopes']

    if 'widgets' not in scopes:
        # can raise some type of error
        return

    base_url = "https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id=" 
    url = base_url + str(user_id)
    api_auth_header = "apiKey " + api_auth_token
    query_headers = {'Authorization': api_auth_header}

    response_objs = list(requests.get(url, params=query_params, headers=query_headers))
    total_widgets = len(response_objs)

    if 'type' in query_params:
        matched_type = query_params['type']
        response_objs = filter(lambda x: x["type"] == matched_type, response_objs)

    if 'created_start' in query_params:
        created_start_dt = parse_date_time(query_params['created_start'])
        response_objs = filter(lambda x: parse_date_time(x['created']) >= created_start_dt, response_objs)

    if 'created_end' in query_params:
        created_end_dt = parse_date_time(query_params['created_end'])
        response_objs = filter(lambda x: parse_date_time(x['created']) <= created_end_dt, response_objs)

    # replace dashes with spaces and capitalize words
    for response_obj in response_objs:
        obj_type = response_obj["type"]
        obj_type_label = [w.capitalize() for w in obj_type.split("-")]
        obj_type_label = ''.join(obj_type_label)
        response_obj['type_label'] = obj_type_label

    matched_res = {'total_widgets_own_by_user': total_widgets, 'matching_items': response_objs}
    '''
    return {
        'total_widgets_own_by_user': 2,
        'matching_items': [
            {
                "id": 0,
                "type": "foo-bar",
                "type_label": "Foo Bar",  # replace dashes with spaces and capitalize words
                "created": datetime.datetime.now().isoformat(), # remember to replace
            }
        ]
    }
    '''
    return make_response(jsonify(matched_res))

def generate_error(message="An error occured"):
    return jsonify(error=message)

def generate_success(message="General success message"):
    return jsonify(success=message)

if __name__ == '__main__':
    app.run()
