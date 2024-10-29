import os
import glob
from flask import send_file, jsonify, current_app
from io import BytesIO
import zipfile

class RulesService:
    def __init__(self):
        self.base_path = './emerging_threat/rules'

    def find_latest_directory(self):
        directories = [d for d in glob.glob(os.path.join(self.base_path, '*')) if os.path.isdir(d)]
        current_app.logger.info(f"Found directories: {directories}")
        if not directories:
            raise FileNotFoundError("No dated directories found.")
        latest_dir = max(directories, key=os.path.getctime)
        current_app.logger.info(f"Latest directory: {latest_dir}")
        return latest_dir

    def get_latest_rules_files(self):
        try:
            latest_dir = self.find_latest_directory()
            current_app.logger.info(f"Serving rules from {latest_dir}")
            rules_files = glob.glob(os.path.join(latest_dir, '*.rules'))
            current_app.logger.info(f"Found rules files: {rules_files}")

            if not rules_files:
                return jsonify({"msg": "No .rules files found in the latest directory"}), 404

            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                for file_path in rules_files:
                    file_name = os.path.basename(file_path)
                    zip_file.write(file_path, file_name)
            
            zip_buffer.seek(0)
            
            return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='rules.zip')
        except Exception as e:
            current_app.logger.error(f"Error in get_latest_rules_files: {str(e)}")
            return jsonify({"error": str(e)}), 500