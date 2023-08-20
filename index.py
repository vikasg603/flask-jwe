import base64
import re
from jwcrypto import jwk, jwe
import json
from flask import Flask, jsonify, request

def decode_base64(data, altchars=b'+/'):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'='* (4 - missing_padding)
    return base64.b64decode(data, altchars)

app = Flask(__name__)

@app.post("/get_payload")
def get_payload():
    if not request.is_json :
        return "Not a JSON Request", 400
    
    if not request.json.get('jwe_token'):
        return "No JWE Token Provided", 400
    
    if not request.json.get("jwe_key") :
        return "No JWE Key Provided", 400

    key = jwk.JWK.from_pem(request.json.get("jwe_key").encode())

    jwe_token = jwe.JWE()
    jwe_token.deserialize(request.json.get("jwe_token"))
    jwe_token.decrypt(key)

    decoded_payload = jwe_token.payload.decode()

    # Decoded payload should be in the format of <header>.<payload>.<signature>
    split_decoded_payload = decoded_payload.split(".")

    if len(split_decoded_payload) != 3 :
        return "Invalid JWE Token", 400
    
    payload_to_return = split_decoded_payload[1]

    base64_decoded_payload = decode_base64(bytes(payload_to_return, 'utf-8'))

    payload_json = json.loads(base64_decoded_payload)

    return jsonify(payload_json), 200
