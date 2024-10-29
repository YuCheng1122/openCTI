import os
import logging
import argparse
from typing import Any, Optional
from pydantic import BaseModel, Extra, validator, field_validator
from datetime import datetime
import json

class JWTConfig(BaseModel, extra=Extra.allow):
    """JWT 相關配置"""
    SECRET_KEY: str = os.environ.get('SECRET_KEY')
    ALGORITHM: str = os.environ.get('ALGORITHM', 'HS256')
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 30))

class FlaskConfig(BaseModel, extra=Extra.allow):
    """Flask 應用配置"""
    SECRET_KEY: str = os.environ.get('SECRET_KEY', 'default-secret-key')
    DEBUG: bool = False
    HOST: str = '0.0.0.0'
    PORT: int = 5000
    LOG_LEVEL: str = 'INFO'

class PathConfig(BaseModel, extra=Extra.allow):
    """路徑配置"""
    base_dir: str = "./threat_intelligence"
    rules_dir: str = "./emerging_threat"
    logs_dir: str = "./logs"
    config_path: str = "./config.json"
    phishing_dir: str = "./phishing_domain"

    def get_daily_folder(self, base: str) -> str:
        """獲取按日期組織的資料夾路徑"""
        today = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(base, today)

    def set_param(self, name: str, value: Any):
        if hasattr(self, name):
            raise AttributeError(f"Parameter {name} already exists.")
        setattr(self, name, value)

    def del_param(self, name: str):
        if hasattr(self, name):
            delattr(self, name)

class EmergingThreatConfig(BaseModel, extra=Extra.allow):
    """Emerging Threat 配置"""
    base_url: str = "https://rules.emergingthreats.net/open/suricata-4.0/rules/"
    max_file_size_kb: float = 500

class APIConfig(BaseModel, extra=Extra.allow):
    """
    API 配置類，存儲所有與 API 連接相關的設定
    """
    api_url: str
    username: str
    password: str
    verify_ssl: bool = False
    limit: int = 2000

    def set_param(self, name: str, value: Any):
        if hasattr(self, name):
            raise AttributeError(f"Parameter {name} already exists.")
        setattr(self, name, value)

    def del_param(self, name: str):
        if hasattr(self, name):
            delattr(self, name)

class MySQLConfig(BaseModel, extra=Extra.allow):
    """MySQL 配置"""
    host: str
    user: str
    password: str
    database: str
    port: int = 3306

class AbuseIPDBConfig(BaseModel, extra=Extra.allow):
    """AbuseIPDB 配置"""
    session: str
    env: str
    xsrf_token: str
    cf_clearance: str
    request_time: int = 10
    batch_size: int = 100

    @field_validator('session', 'xsrf_token', 'cf_clearance')
    @classmethod
    def validate_cookies(cls, v: str) -> str:
        if not v:
            raise ValueError("This field cannot be empty")
        return v

    @field_validator('request_time', 'batch_size')
    @classmethod
    def validate_positive_int(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Must be positive")
        return v

class AbuseIPDBSitemapConfig(BaseModel, extra=Extra.allow):
    """AbuseIPDB Sitemap 配置"""
    pages: int = 200
    base_url: str = 'https://www.abuseipdb.com/sitemap?page='
    request_delay: int = 5
    headers: dict = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }
    cookies: dict

class VirusTotalConfig(BaseModel, extra=Extra.allow):
    """VirusTotal 配置"""
    gsas: str
    utma: str
    utmz: str
    ga: str
    ga_1r8yhmjvfg: str
    ga_blndv9x2jr: str
    ga_e8lnx6hscn: str
    gid: str
    new_privacy_policy_accepted: str
    request_delay: tuple[int, int] = (30, 40)

class Config(BaseModel, extra=Extra.allow):
    """主配置類"""
    flask: FlaskConfig = FlaskConfig()
    path: PathConfig = PathConfig()
    opencti: APIConfig
    emerging_threat: EmergingThreatConfig = EmergingThreatConfig()
    mysql: MySQLConfig 
    jwt: JWTConfig = JWTConfig() 
    abuseipdb: AbuseIPDBConfig 
    abuseipdb_sitemap: AbuseIPDBSitemapConfig 
    virus_total: VirusTotalConfig
    debug: bool = False

    @validator('opencti')
    def validate_opencti_config(cls, v):
        if not v.api_url or not v.username or not v.password:
            raise ValueError("Missing required OpenCTI configuration")
        return v

    def setup_folders(self):
        """創建必要的資料夾"""
        folders = [
            self.path.base_dir,
            self.path.rules_dir,
            self.path.logs_dir
        ]
        for folder in folders:
            os.makedirs(folder, exist_ok=True)

    def setup_logging(self):
        """設置日誌"""
        log_file = os.path.join(
            self.path.logs_dir,
            f"threat_intel_{datetime.now().strftime('%Y-%m-%d')}.log"
        )
        logging.basicConfig(
            level=logging.DEBUG if self.debug else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def set_param(self, name: str, value: Any):
        if hasattr(self, name):
            raise AttributeError(f"Parameter {name} already exists.")
        setattr(self, name, value)

    def del_param(self, name: str):
        if hasattr(self, name):
            delattr(self, name)

def parameter_parser() -> Config:
    """
    解析命令行參數
    """
    parser = argparse.ArgumentParser(description="OpenCTI Data Collector Configuration")
    
    parser.add_argument("--output-dir",
                       dest="output_dir",
                       default="./threat_intelligence",
                       help="Directory for output files")
    
    parser.add_argument("--config-path",
                       dest="config_path",
                       default="./config.json",
                       help="Path to config file")
    
    parser.add_argument("--api-url",
                       dest="api_url",
                       required=True,
                       help="OpenCTI GraphQL API URL")
    
    parser.add_argument("--username",
                       dest="username",
                       required=True,
                       help="OpenCTI username")
    
    parser.add_argument("--password",
                       dest="password",
                       required=True,
                       help="OpenCTI password")
    
    parser.add_argument("--limit",
                       dest="limit",
                       type=int,
                       default=2000,
                       help="Maximum number of indicators to fetch")
    
    parser.add_argument("--debug",
                       dest="debug",
                       action="store_true",
                       help="Enable debug mode")

    args = parser.parse_args()

    return Config(
        path=PathConfig(
            output_dir=args.output_dir,
            config_path=args.config_path
        ),
        api=APIConfig(
            api_url=args.api_url,
            username=args.username,
            password=args.password,
            limit=args.limit
        ),
        debug=args.debug
    )

def read_config(config_file_path: str = "./config/config.json") -> Optional[Config]:
    """
    從檔案讀取配置
    """
    try:
        if os.path.exists(config_file_path):
            with open(config_file_path, encoding="utf-8") as file:
                return Config.parse_raw(file.read())
    except Exception as err:
        logging.error(f"Error reading config: {err}")
    return None

def write_config_to_file(config: Config, config_file_path: str = "./config/config.json") -> None:
    """
    將配置寫入檔案
    """
    try:
        with open(config_file_path, "w", encoding="utf8") as file:
            file.write(config.json(exclude_none=True, indent=2))
        logging.info(f"Config saved to {config_file_path}")
    except Exception as err:
        logging.error(f"Error writing config: {err}")

def init_config() -> Config:
    """初始化配置"""
    try:
        config_path = '/home/docker/opencti/config/config.json'
        
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file {config_path} not found")

        logging.info(f"Reading configuration from {config_path}")
        with open(config_path, encoding="utf-8") as f:
            config_data = json.loads(f.read())
            config = Config.parse_obj(config_data)

        # 驗證配置
        if not config.opencti.api_url or not config.opencti.username or not config.opencti.password:
            raise ValueError("Missing required OpenCTI configuration")

        # 創建目錄
        config.setup_folders()

        return config

    except Exception as e:
        logging.error(f"Failed to initialize configuration: {str(e)}")
        raise RuntimeError(f"Configuration initialization failed: {str(e)}")

# 設置基本日誌配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)