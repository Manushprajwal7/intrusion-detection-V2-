from flask import Flask, jsonify, render_template, Response
from flask_cors import CORS
import json
import pyshark
import threading
import time
import base64
import ipaddress
import requests
import socket
from datetime import datetime

app = Flask(__name__, template_folder='templates')

CORS(app)  # Enable CORS for frontend communication

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)

app.json_encoder = CustomJSONEncoder

class Packets:
    def __init__(self, ipsrc="", time_stamp='', srcport='', transport_layer='', dstnport='', highest_layer='', ipdst=''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstnport = dstnport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer

class apiServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

# Automatically get local machine IP
local_ip = socket.gethostbyname(socket.gethostname())
server = apiServer(local_ip, '3000')

# Set correct network interface (Replace with your valid one)
network_interface = "\\Device\\NPF_{E3335482-8119-414C-BB72-78BA49EF185F}"  # Wi-Fi
capture = pyshark.LiveCapture(interface=network_interface)

def check_if_api_server(packet, server):
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        if packet.ip.src == server.ip or packet.ip.dst == server.ip:
            return True
    return False

def check_if_private_ipadress(ip_addr):
    ip = ipaddress.ip_address(ip_addr)
    return ip.is_private

def report(message):
    temp = json.dumps(message.__dict__, default=str)
    jsonString = temp.encode('ascii')
    b64 = base64.b64encode(jsonString)
    jsonPayload = b64.decode('utf-8').replace("'", '"')
    print(jsonPayload)

    try:
        requests.get(f'http://{server.ip}:{server.port}/api/?{jsonPayload}')
    except requests.ConnectionError:
        pass

def check_packet_filter(packet):
    if check_if_api_server(packet, server):
        return
    if hasattr(packet, 'icmp'):
        DataGram = Packets()
        DataGram.ipdst = packet.ip.dst
        DataGram.ipsrc = packet.ip.src
        DataGram.highest_layer = packet.highest_layer
        DataGram.time_stamp = packet.sniff_time
        report(DataGram)
    if packet.transport_layer in ['TCP', 'UDP']:
        DataGram = Packets()
        if hasattr(packet, 'ipv6'):
            return
        if hasattr(packet, 'ip'):
            if check_if_private_ipadress(packet.ip.src) and check_if_private_ipadress(packet.ip.dst):
                DataGram.ipsrc = packet.ip.src
                DataGram.ipdst = packet.ip.dst
                DataGram.time_stamp = packet.sniff_time
                DataGram.highest_layer = packet.highest_layer
                DataGram.transport_layer = packet.transport_layer
                if hasattr(packet, 'udp'):
                    DataGram.dstnport = packet.udp.dstport
                    DataGram.srcport = packet.udp.srcport
                if hasattr(packet, 'tcp'):
                    DataGram.dstnport = packet.tcp.dstport
                    DataGram.srcport = packet.tcp.srcport
                report(DataGram)

def serialize_packet(packet):
    return {
        'time_stamp': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else '',
        'ipsrc': packet.ip.src if hasattr(packet, 'ip') else '',
        'ipdst': packet.ip.dst if hasattr(packet, 'ip') else '',
        'srcport': packet[packet.transport_layer].srcport if hasattr(packet, packet.transport_layer) and hasattr(packet[packet.transport_layer], 'srcport') else '',
        'dstnport': packet[packet.transport_layer].dstport if hasattr(packet, packet.transport_layer) and hasattr(packet[packet.transport_layer], 'dstport') else '',
        'transport_layer': packet.transport_layer if hasattr(packet, 'transport_layer') else '',
        'highest_layer': packet.highest_layer if hasattr(packet, 'highest_layer') else '',
    }

captured_packets = []

@app.route('/data', methods=['GET'])
def data():
    serialized_packets = [serialize_packet(packet) for packet in captured_packets]
    return jsonify(serialized_packets)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/events')
def events():
    def generate():
        while True:
            if captured_packets:
                packet = captured_packets.pop(0)
                yield f"data: {json.dumps(serialize_packet(packet))}\n\n"
                import sys
                sys.stdout.flush()  # Force immediate output
            time.sleep(1)
    return Response(generate(), mimetype='text/event-stream')


def capture_packets():
    for packet in capture.sniff_continuously(packet_count=500):  # Limit packets to avoid infinite memory usage
        check_packet_filter(packet)
        captured_packets.append(packet)
        if len(captured_packets) > 100:
            captured_packets.pop(0)

if __name__ == '__main__':
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True
    capture_thread.start()
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)

