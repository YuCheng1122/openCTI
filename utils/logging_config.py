# logging_config.py
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from config import Config

def configure_logging(app: Flask, config: Config) -> None:
    """
    配置統一的日誌系統
    
    Args:
        app: Flask 應用實例
        config: 配置實例
    """
    # 設置日誌檔案
    log_file = os.path.join(config.path.logs_dir, 'threat_intel.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # 設置 rotating file handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10000000,  # 10MB
        backupCount=5
    )

    # 設置 console handler
    console_handler = logging.StreamHandler()

    # 統一的日誌格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 設置日誌級別
    log_level = logging.DEBUG if config.debug else logging.INFO
    file_handler.setLevel(log_level)
    console_handler.setLevel(log_level)

    # 配置根日誌器
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger.setLevel(log_level)

    # 配置 Flask logger
    if app:
        app.logger.handlers.clear()
        app.logger.addHandler(file_handler)
        app.logger.addHandler(console_handler)
        app.logger.setLevel(log_level)