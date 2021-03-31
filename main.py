from flask import Flask, request, Response
from waitress import serve
from paste.translogger import TransLogger
from hashlib import sha1
import requests
import hmac
import os

WEBHOOK = os.environ["WEBHOOK"]
SECRET = os.environ["SECRET"].encode()

app = Flask('')


def verify_signature(raw, sign):
    sign_msg = hmac.new(SECRET, raw, sha1).hexdigest()

    return sign_msg == sign


@app.route(f'/{os.environ["ROUTE"]}', methods=['POST'])
def webhook():
    response = Response()
    if verify_signature(
            request.get_data(),
            request.headers.get('X-Gk-Signature', type=str).split('=')[1]):
        response.status_code = 200
        msg_to_send = ''
        try:
            msg_to_send = f'{request.json["action"]} {request.json["card"]["name"]} {request.json["sender"]["username"]}'
        except KeyError:
            msg_to_send = f'{request.json["action"]} {request.json["sender"]["username"]}'
        response.status_code = requests.post(WEBHOOK,
                                             json={
                                                 'text': msg_to_send
                                             }).status_code
    else:
        response.status_code = 401
    return response


def run():
    format_logger = '[%(time)s] %(status)s %(REQUEST_METHOD)s %(REQUEST_URI)s'
    serve(TransLogger(app, format=format_logger),
          host='0.0.0.0',
          port=8080,
          url_scheme='https',
          ident=None)


if __name__ == '__main__':
    run()
