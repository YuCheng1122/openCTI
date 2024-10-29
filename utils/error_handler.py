from flask import jsonify
from werkzeug.exceptions import HTTPException

class APIError(Exception):
    """Base exception class for API errors"""
    def __init__(self, message, code, http_status):
        self.error = {
            "code": code,
            "message": message,
            "description": message,
            "httpStatus": http_status
        }
        self.http_status = http_status

class BadRequestError(APIError):
    """400 Bad Request"""
    def __init__(self, message="Bad request"):
        super().__init__(message, "BAD_REQUEST", 400)

class UnauthorizedError(APIError):
    """401 Unauthorized"""
    def __init__(self, message="Unauthorized"):
        super().__init__(message, "UNAUTHORIZED", 401)

class ForbiddenError(APIError):
    """403 Forbidden"""
    def __init__(self, message="Forbidden"):
        super().__init__(message, "FORBIDDEN", 403)

class NotFoundError(APIError):
    """404 Not Found"""
    def __init__(self, message="Resource not found"):
        super().__init__(message, "NOT_FOUND", 404)

class ConflictError(APIError):
    """409 Conflict"""
    def __init__(self, message="Conflict"):
        super().__init__(message, "CONFLICT", 409)

class InternalServerError(APIError):
    """500 Internal Server Error"""
    def __init__(self, message="Internal server error"):
        super().__init__(message, "INTERNAL_SERVER_ERROR", 500)

def handle_api_error(error):
    response = jsonify({"error": error.error})
    response.status_code = error.http_status
    return response

def handle_werkzeug_error(error):
    response = jsonify({
        "error": {
            "code": str(error.code),
            "message": error.name,
            "description": error.description,
            "httpStatus": error.code
        }
    })
    response.status_code = error.code
    return response

def handle_generic_error(error):
    response = jsonify({
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
            "description": str(error),
            "httpStatus": 500
        }
    })
    response.status_code = 500
    return response

def register_error_handlers(app):
    app.register_error_handler(APIError, handle_api_error)
    app.register_error_handler(HTTPException, handle_werkzeug_error)
    app.register_error_handler(Exception, handle_generic_error)