from flask import jsonify, current_app
from api.auth import requires_auth
from services.threat_intelligence import ThreatIntelligenceService
from services.rules import RulesService
from services.phishing_domain import PhishingDomainService
from services.opencti import OpenCTIFileService, OpenCTIApiClient
from utils.error_handler import APIError, InternalServerError

def configure_routes(app):
    ti_service = ThreatIntelligenceService()
    rules_service = RulesService()
    phishing_service = PhishingDomainService()
    opencti_file_service = OpenCTIFileService()
    
    # 使用新的配置鍵名
    opencti_api_client = OpenCTIApiClient(
        api_url=app.config['OPENCTI_API_URL'],
        username=app.config['OPENCTI_USERNAME'],
        password=app.config['OPENCTI_PASSWORD'],
    )

    @app.route('/')
    def index():
        return jsonify({"message": "Welcome to the API"}), 200

    @app.route('/threat_intelligence', methods=['GET'])
    @requires_auth
    def get_threat_intelligence():
        return ti_service.load_latest_threat_intelligence()

    @app.route('/rules', methods=['GET'])
    @requires_auth
    def get_rules():
        return rules_service.get_latest_rules_files()

    @app.route('/phishing_domain', methods=['GET'])
    @requires_auth
    def get_phishing_domain():
        return phishing_service.find_latest_phishing_file()

    @app.route('/opencti', methods=['GET'])
    @requires_auth
    def get_open_cti():
        return opencti_file_service.get_opencti_data()


    @app.route('/opencti/<ip>', methods=['GET'])
    @requires_auth
    def opencti_ip_info(ip):
        try:
            current_app.logger.info(f"Received request for OpenCTI info for IP: {ip}")
            result = opencti_api_client.get_opencti_ip_info(ip)
            current_app.logger.debug(f"Result from OpenCTIApiClient: {result}")
            if not isinstance(result, dict):
                raise InternalServerError("Unexpected result type from OpenCTI client")
            return jsonify(result), 200
        except APIError as e:
            # The error handler will catch this and format the response
            raise
        except Exception as e:
            current_app.logger.error(f"Unexpected error for IP {ip}: {str(e)}")
            raise InternalServerError("An unexpected error occurred")