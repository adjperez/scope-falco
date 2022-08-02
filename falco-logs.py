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

import encodings
import readline
from sys import stdout
import docker
import re


PLUGIN_ID="falco-logs"
PLUGIN_UNIX_SOCK="/var/run/scope/plugins/" + PLUGIN_ID + ".sock"
DOCKER_SOCK="unix://var/run/docker.sock"
FILE="container_logs"
APP_NAME="Falco_logs"

nodes = {}


LOG_FILE="alert"
APP_NAME="Falco_logs"

LOG_FILE="alert"
APP_NAME="Falco_logs"

def read_container_falco_logs() :
    log_percontainer = {}    
    cli = docker.from_env()
    try:
        c= cli.containers.get("FALCO")
        data=[]
        for line in c.logs().decode('utf-8').split("\n"):        
            try:
                if  (entry := (parse_logs(line))) :
                    data.append(entry)
            except:
                print(APP_NAME+": Error reading Falco container logs")
        return data
    except:
            print(APP_NAME+": Falco container is not running")
            return None
def parse_logs(line):
    data = []
    order = ["date", "type", "description", "id"]
    structure = {}
    details = line.split(" ",2)        
    cli = docker.from_env()
    if (len(details)>=2) and (id := re.search(r'\b(id=)\w+', details[2])):
        try:
            c=cli.containers.get(id.group()[3:])
            details.append(c.id)
            structure = {key:value for key, value in zip(order, details)}
        except:
            return None
    return structure




def update_loop():
    global nodes
    next_call = time.time()  
    #save_containerlogfile()  
    while True:
        #container_logs_lines = read_filelines ()
        data = read_container_falco_logs()
        # Get current timestamp in RFC3339
        timestamp = datetime.datetime.utcnow()
        timestamp = timestamp.isoformat('T') + 'Z'

        # Fetch and convert data to scope data model
        new = {}        
        #for container_id, logs in container_logs_lines.items():
        for entry in data:
            new["%s;<container>" % (entry["id"])] = {
                'latest': {
                    "container-falco-table-Alerts___falco-type" : {
                        'timestamp': timestamp,
                        'value': entry["type"],
                    },
                    "container-falco-table-Alerts___falco-date" : {
                        'timestamp': timestamp,
                        'value': entry["date"],
                    },
                    "container-falco-table-Alerts___falco-description" : {
                        'timestamp': timestamp,
                        'value': entry["description"],
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
