import os
import glob
from flask import send_file, jsonify, current_app

class PhishingDomainService:
    def __init__(self):
        self.directory = './phishing_domain'

    def find_latest_phishing_file(self):
        try:
            list_of_files = glob.glob(os.path.join(self.directory, '*.txt'))
            if not list_of_files:
                return jsonify({"msg": "No phishing domain files found in the directory"}), 404
            
            latest_file = max(list_of_files, key=os.path.getctime)
            current_app.logger.info(f"Serving phishing domain file: {latest_file}")
            return send_file(latest_file, as_attachment=True)
        except Exception as e:
            current_app.logger.error(f"Error in find_latest_phishing_file: {str(e)}")
            return jsonify({"error": str(e)}), 500