#!/usr/bin/env python

import docker
from http.server import BaseHTTPRequestHandler,HTTPServer
import socketserver
import datetime
import errno
import json
import os
import signal
import socket
import threading
import time


PLUGIN_ID="falco-logs"
PLUGIN_UNIX_SOCK="/var/run/scope/plugins/" + PLUGIN_ID + ".sock"
DOCKER_SOCK="unix://var/run/docker.sock"
FILE="container_logs"

nodes = {}


def read_filelines () :
    f = open(FILE, 'r')
    myDict = {}
    for line in f:
        myDict [line.split(",")[0]]=line.split(",")[1]
    f.close
    return myDict

def save_containerlogfile ():
    f = open(FILE, 'w')
    log_percontainer = {}    
    cli = docker.from_env()
    for c in cli.containers.list(all=True):
        f.write ("%s,%s\n" % (c.id, c.logs(tail=1)))
    f.close


def update_loop():
    global nodes
    next_call = time.time()  
    save_containerlogfile()  
    while True:
        container_logs_lines = read_filelines ()

        # Get current timestamp in RFC3339
        timestamp = datetime.datetime.utcnow()
        timestamp = timestamp.isoformat('T') + 'Z'

        # Fetch and convert data to scope data model
        new = {}        
        for container_id, logs in container_logs_lines.items():
            new["%s;<container>" % (container_id)] = {
                'latest': {
                    "container-falco-table-Alerts___falco-type" : {
                        'timestamp': timestamp,
                        'value': "informational",
                    },
                    "container-falco-table-Alerts___falco-date" : {
                        'timestamp': timestamp,
                        'value': timestamp,
                    },
                    "container-falco-table-Alerts___falco-description" : {
                        'timestamp': timestamp,
                        'value': logs,
                    }
                }
            }

        nodes = new
        next_call += 5
        time.sleep(next_call - time.time())

def start_update_loop():
    updateThread = threading.Thread(target=update_loop)
    updateThread.daemon = True
    updateThread.start()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # The logger requires a client_address, but unix sockets don't have
        # one, so we fake it.
        self.client_address = "-"
        # Generate our json body
        body = json.dumps({
            'Plugins': [
                {
                    'id': PLUGIN_ID,
                    'label': 'FALCO',
                    'description': 'Shows security alerts in corresponding containers',
                    'interfaces': ['reporter'],
                    'api_version': '1',
                }
            ],
            'Container': {
                'nodes': nodes,
                # Templates tell the UI how to render this field.
                'table_templates': {
                    'container-falco_table-': {
                        # Key where this data can be found.
                        'id': "container-falco-table-",
                        # Human-friendly field name
                        'label': "Falco Alerts",
                        # Type of table
                        'type': "multicolumn-table",
                        # Prefix to be added in columns
                        'prefix': "container-falco-table-",
                        # Look up the 'id' in the latest object.
                        'from': "latest",
                        # Priorities over 10 are hidden, lower is earlier in the list.
                        'priority': 0.1,
                        "columns": [ 
                            { 
                                "id": "falco-type", 
                                "label": "Type", 
                                "dataType": "" 
                            }, 
                            { 
                                "id": "falco-date", 
                                "label": "Date", 
                                "dataType": "" 
                            }, 
                            { 
                                "id": "falco-description", 
                                "label": "Description", 
                                "dataType": "" 
                            }, 
                        ],
                    },
                },
                'metadata_templates': {
                    'falco_count': {
                        # Key where this data can be found.
                        'id': "falco-metric",
                        # Human-friendly field name
                        'label': "# Falco Agent",
                        # Look up the 'id' in the latest object.
                        'from': "latest",
                        # Priorities over 10 are hidden, lower is earlier in the list.
                        'priority': 0.1,
                    },
                },
            },
        })

        # Send the headers
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()

        # Send the body
        self.wfile.write(body.encode())
        time.sleep(5)

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def delete_socket_file():
    if os.path.exists(PLUGIN_UNIX_SOCK):
        os.remove(PLUGIN_UNIX_SOCK)

def sig_handler(b, a):
    delete_socket_file()
    exit(0)

def main():
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    start_update_loop()

    # Ensure the socket directory exists
    mkdir_p(os.path.dirname(PLUGIN_UNIX_SOCK))
    # Remove existing socket in case it was left behind
    delete_socket_file()
    # Listen for connections on the unix socket
    server = socketserver.UnixStreamServer(PLUGIN_UNIX_SOCK, Handler)
    try:
        server.serve_forever()
    except:
        delete_socket_file()
        raise

main()
