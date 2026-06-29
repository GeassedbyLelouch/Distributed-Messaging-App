#protocol.py
import json

def encode(msg):
    return json.dumps(msg).encode()

def decode(data):
    return json.loads(data.decode())
