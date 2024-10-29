import json
import os
import glob
from datetime import datetime, timedelta
from flask import jsonify, current_app

class ThreatIntelligenceService:
    def __init__(self):
        self.directory = './threat_intelligence'

    def find_latest_json_files(self, days=7):
        list_of_files = glob.glob(os.path.join(self.directory, '*.json'))
        if not list_of_files:
            return []

        list_of_files.sort(key=os.path.getctime, reverse=True)
        recent_files = []
        cutoff_time = datetime.now() - timedelta(days=days)
        
        for file in list_of_files:
            file_time = datetime.fromtimestamp(os.path.getctime(file))
            if file_time >= cutoff_time:
                recent_files.append(file)
                if len(recent_files) >= 7:
                    break

        return recent_files

    def load_latest_threat_intelligence(self):
        try:
            current_app.logger.info(f"Searching for JSON files in directory: {self.directory}")
            
            latest_files = self.find_latest_json_files(days=7)
            current_app.logger.info(f"Found {len(latest_files)} JSON files from the last 7 days")
            
            if not latest_files:
                raise FileNotFoundError("No JSON files found in the directory for the last 7 days.")
            
            merged_data = []
            for file in latest_files:
                current_app.logger.info(f"Processing file: {file}")
                try:
                    with open(file, 'r') as f:
                        content = f.read()
                        if not content.strip():
                            current_app.logger.error(f"The JSON file {file} is empty.")
                            raise ValueError(f"The JSON file {file} is empty.")
                        data = json.loads(content)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    item.pop('description', None)
                                    merged_data.append(item)
                        elif isinstance(data, dict):
                            data.pop('description', None)
                            merged_data.append(data)
                        else:
                            current_app.logger.error(f"Unexpected data format in file {file}")
                            raise ValueError(f"Unexpected data format in file {file}")
                        current_app.logger.info(f"Successfully processed file: {file}")
                except json.JSONDecodeError as e:
                    current_app.logger.error(f"JSON decode error in file {file}: {str(e)}")
                    raise
                except Exception as e:
                    current_app.logger.error(f"Error processing file {file}: {str(e)}")
                    raise
            
            current_app.logger.info(f"Successfully loaded data from {len(latest_files)} files. Total objects: {len(merged_data)}")
            return jsonify(merged_data), 200
        except Exception as e:
            current_app.logger.error(f"Error in load_latest_threat_intelligence: {str(e)}")
            return jsonify({"error": str(e)}), 500