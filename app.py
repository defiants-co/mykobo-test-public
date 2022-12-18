from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    redirect
)
from flask_cors import (
    CORS,
    cross_origin
)
import hashlib
import hmac
import json
import logging
import time
import uuid

import requests

app = Flask(__name__)

config = json.load(
    open('config.json')
)

SUMSUB_SECRET_KEY = config['SECRET']
SUMSUB_APP_TOKEN = config['APP_TOKEN']  
SUMSUB_TEST_BASE_URL = "https://api.sumsub.com"
REQUEST_TIMEOUT = 60

def sign_request(request: requests.Request) -> requests.PreparedRequest:
    prepared_request = request.prepare()
    now = int(time.time())
    method = request.method.upper()
    path_url = prepared_request.path_url  # includes encoded query params
    # could be None so we use an empty **byte** string here
    body = b'' if prepared_request.body is None else prepared_request.body
    if type(body) == str:
        body = body.encode('utf-8')
    data_to_sign = str(now).encode('utf-8') + method.encode('utf-8') + path_url.encode('utf-8') + body
    # hmac needs bytes
    signature = hmac.new(
        SUMSUB_SECRET_KEY.encode('utf-8'),
        data_to_sign,
        digestmod=hashlib.sha256
    )
    prepared_request.headers['X-App-Token'] = SUMSUB_APP_TOKEN
    prepared_request.headers['X-App-Access-Ts'] = str(now)
    prepared_request.headers['X-App-Access-Sig'] = signature.hexdigest()
    return prepared_request



def get_access_token(external_user_id, level_name):
    # https://developers.sumsub.com/api-reference/#access-tokens-for-sdks
    params = {'userId': external_user_id, 'ttlInSecs': '600', 'levelName': level_name}
    headers = {'Content-Type': 'application/json',
               'Content-Encoding': 'utf-8'
               }
    resp = sign_request(requests.Request('POST', SUMSUB_TEST_BASE_URL + '/resources/accessTokens',
        params=params,
        headers=headers)
    )
    s = requests.Session()
    response = s.send(resp, timeout=REQUEST_TIMEOUT)
    token = (response.json()['token'])

    return token

@app.route('/<key>')
@cross_origin()
def return_access_token(key):
    access_token = get_access_token(key,'basic-kyc-level')
    return jsonify({
        "access_token" : access_token
    })

# In a real environment, there would be a transaction_id, that denotes the deposit in question, and a signed JWT from a challenge transaction to authenticate the user. Then, amounts, withdrawal requests, SEP12 and SEP24 workflows are processed.

@app.route('/')
def index():
    return redirect('/create_transfer')

@app.route('/create_transfer')
def create_transfer():
    return render_template('init_workflow.html')

@app.route('/kyc')
def kyc():
    return render_template('kyc_workflow.html')

if __name__ == "__main__":
    app.run(debug=True)

