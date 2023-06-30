import json
import os
from flask import Flask, request
from flask_restful import Api, Resource
import requests
import urllib3

server = Flask(__name__)
api = Api(server)

username = os.getenv('UNIFI_USERNAME', 'redacted')
password = os.getenv('PASSWORD', 'redacted')
ipAddress = os.getenv('IP_ADDRESS', '192.168.1.1')
port = os.getenv('PORT', '443')
site = os.getenv('SITE', None)
model = os.getenv('MODEL', 'udmp')
session = None

urllib3.disable_warnings()

class CheckCred(Resource):
    def post(self, Action):
        if Action == 'get':
            return self.returnCreds()
        elif Action == 'test':
            return self.testCreds()
        elif Action == 'update':
            return self.updateCreds()
        else:
            return "Invalid function"

    def returnCreds(self):
        return {
            "username": username,
            "password": password,
            "ipAddress": ipAddress,
            "port": port,
            "site": site,
            "model": model
        }

    def testCreds(self):
        global username
        global password

        url = getUri(type="login")
        session = requests.Session()
        session.verify = False

        data = {
            "username": username,
            "password": password,
        }

        print(username)
        print(password)

        response = session.post(url, data=data)
        
        if response.status_code == 200:
            return "Credentials OK"
        else:
            try:
                error_data = response.json()
                error_code = error_data.get("code")
                error_message = error_data.get("message")
                return f"Credentials not OK. Error Code: {error_code}. Error Message: {error_message}"
            except ValueError:
                return "Credentials not OK. Unable to parse error response."

    def updateCreds(self):
            data = request.get_json()  # Assuming the data is sent in JSON format

            # Extract the fields from the data and update the corresponding variables
            new_username = data.get('username')
            new_password = data.get('password')
            new_ipAddress = data.get('ipAddress')
            new_port = data.get('port')
            new_site = data.get('site')
            new_model = data.get('model')

            # Update the global variables with the new values
            global username
            global password
            global ipAddress
            global port
            global site
            global model

            username = new_username if new_username else username
            password = new_password if new_password else password
            ipAddress = new_ipAddress if new_ipAddress else ipAddress
            port = new_port if new_port else port
            site = new_site if new_site else site
            model = new_model if new_model else model

            return "Data updated"

def authenticate():
    global session
    url = getUri(type="login")
    session = requests.Session()
    session.verify = False

    data = {
        "username": username,
        "password": password,
    }

    response = session.post(url, data=data)
        
    if response.status_code == 200:
        csrf = response.headers.get('X-CSRF-Token')
        session.headers['X-CSRF-Token'] = csrf
        return session
    else:
        try:
            error_data = response.json()
            error_code = error_data.get("code")
            error_message = error_data.get("message")
            return f"Error Code: {error_code}. Error Message: {error_message}"
        except ValueError:
            return "Authentication failed. Unable to parse error response."

def logOut():
    global session
    uri = getUri()
    decorator = "/api/logout"
    uri = uri + decorator
    r = session.post(uri)

    if r.status_code == 200:
        return "Logged out successfully"
    else:
        return "Couldnt log out"

class GetData(Resource):
    def get(self, Type):
        if Type == 'get':
            return self.returnCreds()
        elif Type == 'test':
            return self.testCreds()
        else:
            return "Invalid function"

def getUri(type=""):
    global ipAddress
    global port
    global site
    global model

    if site is not None:
        site = str(site)
    else:
        site = "default"

    if model == "udmp":
        Uri = "https://" + str(ipAddress) + ":" + str(port) + "/proxy/network"
        LoginUri = "https://" + str(ipAddress) + ":" + str(port) + "/api/auth/login"
    elif model == "other":
        Uri = "https://" + str(ipAddress) + ":" + str(port)
        LoginUri = "https://" + str(ipAddress) + ":" + str(port) + "/api/login"
    else:
        return ""
    
    if type == "login":
        return LoginUri
    else:
        return Uri

api.add_resource(CheckCred, "/CheckCred/<string:Action>")
api.add_resource(GetData, "/GetData/<string:Type>")

if __name__ == "__main__":
    server.run(debug=True, host='0.0.0.0')
