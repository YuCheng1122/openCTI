import threading
import schedule
import time
from flask import Flask
from api.routes import configure_routes
from utils.error_handler import register_error_handlers
from utils.logging_config import configure_logging
from config import init_config
from collectors.opencti_collector import OpenCTICollector
from collectors.emerging_threat_collector import EmergingThreatCollector
from collectors.phishing_collector import PhishingCollector
from collectors.phishing_data_collector import PhishingDataCollector
from collectors.abuseipdb_collector import AbuseIPDBCollector
from collectors.abuseipdb_sitemap_collector import AbuseIPDBSitemapCollector
from collectors.virustotal_collector import VirusTotalCollector

class FlaskApp:
    def __init__(self):
        self.config = init_config()
        self.app = Flask(__name__)
        self.setup_app()
        
        # 初始化收集器標誌
        self.collectors_initialized = False
        try:
            self.setup_collectors()
            self.collectors_initialized = True
            self.start_scheduler()
        except Exception as e:
            self.app.logger.error(f"Failed to initialize collectors: {e}")

    def setup_app(self):
        """設置 Flask 應用"""
        # 將配置轉換為 Flask 格式
        flask_config = {
            'SECRET_KEY': self.config.flask.SECRET_KEY,
            'DEBUG': self.config.flask.DEBUG,

            # OpenCTI 配置 
            'OPENCTI_API_URL': self.config.opencti.api_url,
            'OPENCTI_USERNAME': self.config.opencti.username,
            'OPENCTI_PASSWORD': self.config.opencti.password,
            'OPENCTI_VERIFY_SSL': self.config.opencti.verify_ssl,
            'OPENCTI_LIMIT': self.config.opencti.limit,
        
            # JWT 配置
            'JWT_SECRET_KEY': self.config.jwt.SECRET_KEY,
            'JWT_ALGORITHM': self.config.jwt.ALGORITHM,
            'JWT_ACCESS_TOKEN_EXPIRE_MINUTES': self.config.jwt.ACCESS_TOKEN_EXPIRE_MINUTES
            }
    
        self.app.config.update(flask_config)

        # 配置日誌
        configure_logging(self.app, self.config)
        
        # 設置路由和錯誤處理
        with self.app.app_context():
            configure_routes(self.app)
            register_error_handlers(self.app)

    def setup_collectors(self):
        """設置數據收集器"""
        self.app.logger.info("Initializing collectors...")

        # OpenCTI 收集器
        try:
            self.opencti_collector = OpenCTICollector(self.config)
            self.app.logger.info("OpenCTI collector initialized successfully")
        except Exception as e:
            self.app.logger.error(f"Failed to initialize OpenCTI collector: {e}")
            raise

        # Emerging Threats 收集器
        try:
            self.et_collector = EmergingThreatCollector(self.config)
            self.app.logger.info("Emerging Threats collector initialized successfully")
        except Exception as e:
            self.app.logger.error(f"Failed to initialize Emerging Threats collector: {e}")
            raise

        # 實時釣魚數據收集器
        try:
            self.phishing_collector = PhishingCollector(self.config)
            self.app.logger.info("Phishing collector initialized successfully")
            
            # 釣魚數據匯總收集器（從數據庫到文件）
            self.phishing_data_collector = PhishingDataCollector(self.config)
            self.app.logger.info("Phishing data collector initialized successfully")
        except Exception as e:
            self.app.logger.error(f"Failed to initialize Phishing collectors: {e}")
            raise

        # AbuseIPDB 收集器
        try:
            self.abuseipdb_collector = AbuseIPDBCollector(self.config)
            self.abuseipdb_thread = None 
            self.app.logger.info("AbuseIPDB collector initialized successfully")
        except Exception as e:
            self.app.logger.error(f"Failed to initialize AbuseIPDB collectors: {e}")
            raise

        # AbuseIPDB Sitemap 收集器
        try:
            self.abuseipdb_sitemap_collector = AbuseIPDBSitemapCollector(self.config)
            self.app.logger.info("AbuseIPDB sitemap collector initialized successfully")
        except Exception as e:
            self.app.logger.error(f"Failed to initialize AbuseIPDB sitemap collector: {e}")
            raise

        # VirusTotal 收集器            
        try:
            self.virustotal_collector = VirusTotalCollector(self.config)
            self.virustotal_thread = None 
            self.app.logger.info("VirusTotal collector initialized successfully")
        except Exception as e:
            self.app.logger.error(f"Failed to initialize VirusTotal collectors: {e}")
            raise

    def run_opencti_collector(self):
        """運行 OpenCTI 收集器"""
        try:
            self.app.logger.info("Starting OpenCTI data collection...")
            self.opencti_collector.save_indicators()
            self.app.logger.info("OpenCTI data collection completed successfully")
        except Exception as e:
            self.app.logger.error(f"Error in OpenCTI collector: {e}")

    def run_et_collector(self):
        """運行 Emerging Threats 收集器"""
        try:
            self.app.logger.info("Starting Emerging Threats rules collection...")
            self.et_collector.collect()
            self.app.logger.info("Emerging Threats rules collection completed successfully")
        except Exception as e:
            self.app.logger.error(f"Error in Emerging Threats collector: {e}")
    
    def run_phishing_collector(self):
        """運行 OPENPHISHING 收集器"""
        try:
            self.app.logger.info("Starting Phishing data collection...")
            self.phishing_collector.collect()
            self.app.logger.info("Phishing data collection completed successfully")
        except Exception as e:
            self.app.logger.error(f"Error in Phishing collector: {e}")

    def run_phishing_data_collector(self):
        """運行 Phishing Data 收集器"""
        try:
            self.app.logger.info("Starting Phishing data collection...")
            self.phishing_data_collector.collect()
            self.app.logger.info("Phishing data collection completed successfully")
        except Exception as e:
            self.app.logger.error(f"Error in Phishing data collector: {e}")

    def run_abuseipdb_sitemap_collector(self):
        """運行 sitemap 收集器"""
        try:
            self.app.logger.info("Starting AbuseIPDB sitemap collection...")
            self.abuseipdb_sitemap_collector.collect()
            self.app.logger.info("AbuseIPDB sitemap collection completed")
        except Exception as e:
            self.app.logger.error(f"Error in AbuseIPDB sitemap collector: {e}")

    def start_abuseipdb_collector(self):
        """啟動 AbuseIPDB 持續收集"""
        if not self.abuseipdb_thread or not self.abuseipdb_thread.is_alive():
            self.abuseipdb_thread = threading.Thread(
                target=self.abuseipdb_collector.collect_continuous
            )
            self.abuseipdb_thread.daemon = True
            self.abuseipdb_thread.start()
            self.app.logger.info("AbuseIPDB continuous collection started")
    
    def start_virustotal_collector(self):
        """啟動 VirusTotal 持續收集"""
        if not self.virustotal_thread or not self.virustotal_thread.is_alive():
            self.virustotal_thread = threading.Thread(
                target=self.virustotal_collector.collect_continuous
            )
            self.virustotal_thread.daemon = True
            try:
                self.virustotal_thread.start()
                self.app.logger.info("VirusTotal continuous collection started")
            except Exception as e:
                self.app.logger.error(f"Failed to start VirusTotal collector thread: {e}")
                raise
    
    def start_scheduler(self):
        """啟動排程器"""
        if not self.collectors_initialized:
            self.app.logger.error("Cannot start scheduler: collectors not initialized!")
            return

        def run_schedule():
            self.app.logger.info("Scheduler thread started")
            while True:
                try:
                    schedule.run_pending()
                    time.sleep(1)  # 改為每秒檢查一次以確保及時性
                except Exception as e:
                    self.app.logger.error(f"Scheduler error: {e}")
        try:
            # 設置不同的執行頻率
            schedule.every(30).seconds.do(self.run_phishing_collector)    # 每 30 秒執行一次
            schedule.every(1).hours.do(self.run_opencti_collector)        # 每小時執行一次
            schedule.every(1).days.do(self.run_et_collector)               # 每天執行一次
            schedule.every(1).days.at("23:59").do(self.run_phishing_data_collector) # 每天23:59執行一次
            schedule.every().day.at("02:00").do(self.run_abuseipdb_sitemap_collector) # 每天02:00執行一次

            #不停執行abuseipdb收集            
            self.start_abuseipdb_collector()
            #不停執行virustotal收集            
            self.start_virustotal_collector()

            # 立即執行一次收集
            self.app.logger.info("Running initial collection...")
            #self.run_opencti_collector()
            #self.run_et_collector()
            #self.run_phishing_collector()
            #self.run_phishing_data_collector()
            # self.run_abuseipdb_sitemap_collector()
            
            # 在背景執行排程器
            scheduler_thread = threading.Thread(target=run_schedule)
            scheduler_thread.daemon = True
            scheduler_thread.start()
            self.app.logger.info("Scheduler started successfully")
            
        except Exception as e:
            self.app.logger.error(f"Failed to start scheduler: {e}")
            raise

    def run(self):
        """運行應用"""
        try:
            self.app.logger.info(f"Starting Flask application on {self.config.flask.HOST}:{self.config.flask.PORT}")
            self.app.run(
                host=self.config.flask.HOST,
                port=self.config.flask.PORT,
                debug=self.config.flask.DEBUG
            )
        except Exception as e:     
            self.app.logger.error(f"Failed to start Flask application: {e}")
            raise

def create_app():
    """創建應用實例"""
    flask_app = FlaskApp()
    return flask_app.app

if __name__ == '__main__':
    flask_app = FlaskApp()
    flask_app.run()