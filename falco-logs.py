#!/usr/bin/env python

from urllib.parse import urlparse
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
from collections import ChainMap

import encodings
import readline
from sys import stdout
import docker
import re
#import simplejson

PLUGIN_ID="falco-logs"
PLUGIN_UNIX_SOCK="/var/run/scope/plugins/" + PLUGIN_ID + ".sock"
DOCKER_SOCK="unix://var/run/docker.sock"
FILE="container_logs"
APP_NAME="Falco_logs"

#Containers to be delivered in report
nodes = {}
#Containers that have enabled Falco alerts
nodes_on = []
#Containers that have not enabled Falco alerts
nodes_off = []


LOG_FILE="alert"
APP_NAME="Falco_logs"

def read_container_falco_logs(id) :    
    cli = docker.from_env()
    #c= cli.containers.get("FALCO")
    c=cli.containers.list()
    falco_id=""
    for c in cli.containers.list():        
        if "falcosecurity" in str(c.image):            
            #print("FALCO FOUND!", c.id)
            falco_id=c.id
            break    
    data=[]
    for line in cli.containers.get(falco_id).logs().decode('utf-8').split("\n"):        
        try:            
            #Adding support for Kubernetes container search
            if  (re.search(r'\b(id=%s)\w+' % (id), line)) or (re.search(r'\b(container_id=%s)\w+' % (id), line)) :                                                
                entry = (parse_logs(line))            
                if entry!=None:
                        data.append(entry)
        except:
            print(APP_NAME+": Error reading Falco container logs, is Falco container running?")
            
    return data

def parse_logs(line):
    data = []
    order = ["date", "type", "description", "id"]
    structure = {}
    details = line.split(" ",2)        
    cli = docker.from_env()
    if (len(details)>=2) and (id := re.search(r'(id=)\w+', details[2])):
        try:
            c=cli.containers.get(id.group()[3:])        
            details.append(c.id)
            structure = {key:value for key, value in zip(order, details)}
        except:
            return None
    return structure


def get_all_scope_containers_ids ():
    data = []
    cli = docker.from_env()
    for c in cli.containers.list():
        data.append("%s;<container>" % (c.id))
    return data

def update_loop():
    global nodes,nodes_on,nodes_off
    next_call = time.time()  
    #save_containerlogfile()  
    nodes_off = get_all_scope_containers_ids ()        
    
    while True:
        # Get current timestamp in RFC3339
        timestamp = datetime.datetime.utcnow()
        timestamp = timestamp.isoformat('T') + 'Z'
        new={}
 
        dead=True
        for nodeoff in nodes_off:
            short_id=nodeoff[0:8]            
            new[nodeoff] = {
                    'latestControls': { 
                        "falco_on": {
                            'timestamp': timestamp,
                            'value': {
                                'dead': not dead,
                            }
                        },
                        "falco_off": {
                            'timestamp': timestamp,
                            'value': {
                                'dead': dead,
                            }
                        }                          
                    }                       
            }   

        for nodeon in nodes_on:
            short_id=nodeon[0:8]
            new[nodeon]=dict()
            new[nodeon]['latest']={}
            index=1
            for entry in read_container_falco_logs(short_id):
                    
                    new[nodeon]['latest']["container-falco-table-Alerts"+("%s" % index)+"___falco-type"] = {
                         'timestamp': timestamp,
                          'value': entry["type"]
                    }

                    new[nodeon]['latest']["container-falco-table-Alerts"+("%s" % index)+"___falco-date"] = {
                         'timestamp': timestamp,
                          'value': entry["date"]
                    }

                    new[nodeon]['latest']["container-falco-table-Alerts"+("%s" % index)+"___falco-description"] = {
                         'timestamp': timestamp,
                          'value': entry["description"]
                    }

                    index=index+1
            #If there is not any Falco alert, then print None
            if not bool(new[nodeon]['latest']):
                    new[nodeon]['latest']["container-falco-table-Alerts"+("%s" % index)+"___falco-type"] = {
                         'timestamp': timestamp,
                          'value': "None"
                    }

                    new[nodeon]['latest']["container-falco-table-Alerts"+("%s" % index)+"___falco-date"] = {
                         'timestamp': timestamp,
                          'value': "None"
                    }

                    new[nodeon]['latest']["container-falco-table-Alerts"+("%s" % index)+"___falco-description"] = {
                         'timestamp': timestamp,
                          'value': "None"
                    }                
            controls = {

                                "falco_on": {
                                    'timestamp': timestamp,
                                    'value': {
                                        'dead': dead,
                                    }
                                },
                                "falco_off": {
                                    'timestamp': timestamp,
                                    'value': {
                                        'dead': not dead,
                                    }
                                }                                                    
            }
            new[nodeon]['latestControls']=controls
                
        
        nodes = new                
        next_call += 5
        
        time.sleep(next_call - time.time())

def start_update_loop():
    updateThread = threading.Thread(target=update_loop)
    updateThread.daemon = True
    updateThread.start()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.log_extra = ''
        path = urlparse(self.path)[2].lower()
        if path == '/control':
            self.do_control()
        else:
            self.send_response(404)
            self.send_header('Content-length', 0)
            self.end_headers()
        
    def do_GET(self):
        self.log_extra = ''
        path = urlparse(self.path)[2].lower()
        if path == '/report':
            self.do_report()
        else:
            self.send_response(404)
            self.send_header('Content-length', 0)
            self.end_headers()

    def do_control(self):        
        global nodes_on, nodes_off
        raw = (self.rfile.read(int(self.headers['content-length']))).decode('utf-8')
        raw_dict = json.loads(raw)
        if raw_dict['Control'] == "falco_on":            
            nodes_on.append(raw_dict['NodeID'])
            nodes_off.remove(raw_dict['NodeID'])
        
        elif raw_dict['Control'] == "falco_off":
            nodes_on.remove(raw_dict['NodeID'])
            nodes_off.append(raw_dict['NodeID'])
        self.do_report()    


    def do_report(self):
        # The logger requires a client_address, but unix sockets don't have
        # one, so we fake it.
        self.client_address = "-"
        # Generate our json body
        
        #nodes_dump = json.dumps(nodes).replace("[","{").replace("]","}")        
        body = json.dumps({
            'Plugins': [
                {
                    'id': PLUGIN_ID,
                    'label': 'FALCO',
                    'description': 'Shows security alerts in corresponding containers',
                    'interfaces': ['reporter', 'controller'],
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
                'controls': {
                    'falco_on': {
                        # Key where this data can be found.
                        'id': "falco_on",
                        # Human-friendly field name
                        'human': "Retrieve falco alerts",
                        # Icon to show.
                        'icon': "fa-gears",
                        # Lower is earlier in the list.
                        'rank': 9
                    },
                      'falco_off': {
                        # Key where this data can be found.
                        'id': "falco_off",
                        # Human-friendly field name
                        'human': "Remove falco alerts",
                        # Icon to show.
                        'icon': "fa-times-circle",
                        # Lower is earlier in the list.
                        'rank': 9
                    }
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
