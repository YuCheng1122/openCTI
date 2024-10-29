import os
import json
from datetime import datetime
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError, SSLError
from utils.error_handler import BadRequestError, UnauthorizedError, NotFoundError, InternalServerError
import urllib3
from flask import jsonify, current_app

class OpenCTIFileService:
    def __init__(self, directory='./open_cti'):
        self.directory = directory

    def get_opencti_data(self):
        try:
            json_files = [f for f in os.listdir(self.directory) if f.endswith('.json')]
            
            if not json_files:
                raise FileNotFoundError("No JSON files found in the directory")
            
            newest_file = max(json_files, key=lambda f: os.path.getmtime(os.path.join(self.directory, f)))
            file_path = os.path.join(self.directory, newest_file)
            
            with open(file_path, 'r') as file:
                data = json.load(file)
            
            if not isinstance(data, dict) or 'indicators' not in data:
                raise ValueError("Invalid JSON structure")
            
            response_data = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": data
            }
            
            return jsonify(response_data), 200
        except Exception as e:
            current_app.logger.error(f"Error in get_opencti_data: {str(e)}")
            return jsonify({"error": str(e)}), 500

class OpenCTIApiClient:
    def __init__(self, api_url, username, password):
        self.api_url = api_url
        self.auth = (username, password)
        self.headers = {'Content-Type': 'application/json'}

    def query(self, query):
        try:
            response = requests.post(
                self.api_url, 
                auth=self.auth, 
                headers=self.headers, 
                json={'query': query}, 
                verify=False,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Timeout:
            raise InternalServerError("Connection to OpenCTI timed out")
        except ConnectionError:
            raise InternalServerError("Failed to connect to OpenCTI server")
        except SSLError:
            raise InternalServerError("SSL error occurred while connecting to OpenCTI")
        except RequestException as e:
            if e.response is not None:
                if e.response.status_code == 400:
                    raise BadRequestError("Invalid request to OpenCTI")
                elif e.response.status_code == 401:
                    raise UnauthorizedError("Unauthorized access to OpenCTI")
                elif e.response.status_code == 404:
                    raise NotFoundError("Resource not found in OpenCTI")
            raise InternalServerError(f"Error occurred while querying OpenCTI: {str(e)}")

    def get_indicator_by_ip(self, ip_address):
        query = f'''
        {{
          indicators(filters: {{
            mode: and,
            filters: [
              {{ key: "name", values: ["{ip_address}"] }},
              {{ key: "entity_type", values: ["Indicator"] }}
            ],
            filterGroups: []
          }}) {{
            edges {{
              node {{
                id
                name
                pattern
                description
                created_at
                createdBy {{
                  name
                }}
                x_opencti_score
                objectLabel {{
                  value
                }}
              }}
            }}
          }}
        }}
        '''
        return self.query(query)

    def get_opencti_ip_info(self, ip):
        try:
            current_app.logger.info(f"Querying OpenCTI for IP: {ip}")
            result = self.get_indicator_by_ip(ip)
            
            current_app.logger.debug(f"Raw result from OpenCTI: {result}")
            
            if result and isinstance(result, dict) and 'data' in result and 'indicators' in result['data']:
                indicators = result['data']['indicators']['edges']
                if indicators:
                    node = indicators[0]['node']
                    formatted_indicator = {
                        "value": node.get('name', ''),
                        "score": node.get('x_opencti_score', 0),
                        "type": self.determine_type(node.get('pattern', '')),
                        "labels": [label.get('value', '') for label in node.get('objectLabel', [])],
                        "create_date": node.get('created_at', ''),
                        "author": node.get('createdBy', {}).get('name', 'Unknown')
                    }
                    current_app.logger.info(f"Successfully retrieved data for IP: {ip}")
                    return {"ip_list": [formatted_indicator]}
                else:
                    current_app.logger.warning(f"No indicator found for IP: {ip}")
                    raise NotFoundError(f"No indicator found for IP: {ip}")
            else:
                current_app.logger.error(f"Unexpected result structure from OpenCTI for IP: {ip}")
                raise InternalServerError("Failed to retrieve data from OpenCTI")
        except Exception as e:
            current_app.logger.error(f"Error in get_opencti_ip_info for IP {ip}: {str(e)}")
            raise

    @staticmethod
    def determine_type(pattern):
        if "ipv4-addr" in pattern:
            return "ipv4"
        elif "ipv6-addr" in pattern:
            return "ipv6"
        elif "domain-name" in pattern:
            return "domain"
        elif "url" in pattern:
            return "url"
        elif "email-addr" in pattern:
            return "email"
        else:
            return "unknown"