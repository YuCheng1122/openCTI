import requests
import logging
import time
import re
from bs4 import BeautifulSoup
import mysql.connector
from datetime import datetime
from config import Config


class AbuseIPDBSitemapCollector:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.base_url = self.config.abuseipdb_sitemap.base_url
        self.pages = self.config.abuseipdb_sitemap.pages
        self.ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        self.processed_ips = set()

        self.db_config = {
            'host': config.mysql.host,
            'user': config.mysql.user,
            'password': config.mysql.password,
            'database': config.mysql.database,
            'port': config.mysql.port
        }
        
        # 硬編碼 headers 和 cookies
        self.headers = config.abuseipdb_sitemap.headers
        self.cookies = config.abuseipdb_sitemap.cookies
        self.session = requests.Session()

    def load_existing_ips(self):
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM Combined_IP_Score")
            existing_ips = set(ip[0] for ip in cursor.fetchall())
            cursor.close()
            conn.close()
            self.processed_ips.update(existing_ips)
            self.logger.info(f"Loaded {len(existing_ips)} existing IPs from the database.")
        except mysql.connector.Error as e:
            self.logger.error(f"Error loading existing IPs: {e}")

    def save_ips_to_db(self, ips):
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()

            new_ips = 0
            for ip in ips:
                if ip and isinstance(ip, str) and ip not in self.processed_ips:
                    try:
                        cursor.execute("""
                            INSERT INTO Combined_IP_Score (ip_address, score)
                            VALUES (%s, %s)
                            ON DUPLICATE KEY UPDATE ip_address = ip_address
                        """, (ip, 0))
                        self.processed_ips.add(ip)
                        new_ips += 1
                    except mysql.connector.Error as e:
                        logging.error(f"Error inserting IP {ip}: {e}")

            conn.commit()
            cursor.close()
            conn.close()
            return new_ips
        except mysql.connector.Error as e:
            self.logger.error(f"Database connection error: {e}")
            return 0
        
    def initialize_session(self):
        """初始化 session"""
        try:
            self.session.headers.update(self.headers)
            response = self.session.get('https://www.abuseipdb.com', cookies=self.cookies)
            response.raise_for_status()
            self.logger.info("Session initialized successfully")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error initializing session: {e}")

    def fetch_page(self, page):
        """獲取頁面內容"""
        try:
            url = f"{self.base_url}{page}"
            self.logger.info(f"Fetching page {page} from: {url}")
            response = self.session.get(url, cookies=self.cookies)
            
            if response.status_code == 200:
                return response
            else:
                self.logger.error(f"Failed to fetch page {page}. Status code: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching page {page}: {e}")
            return None

    def parse_ips(self, content):
        """解析頁面中的 IP"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            a_tags = soup.find_all('a', href=True)
            return [tag.get_text(strip=True) 
                   for tag in a_tags 
                   if re.match(self.ip_pattern, tag.get_text(strip=True))]
        except Exception as e:
            self.logger.error(f"Error parsing IPs: {e}")
            return []

    def collect(self):
        """執行收集過程"""
        start_time = datetime.now()
        self.logger.info(f"Starting sitemap collection at {start_time}")
        
        try:
            self.initialize_session()
            self.load_existing_ips()
            
            for page in range(1, self.pages + 1):
                try:
                    response = self.fetch_page(page)
                    if response and response.status_code == 200:
                        ips = self.parse_ips(response.content)
                        if ips:
                            new_ips = self.save_ips_to_db(ips)
                            self.logger.info(f"Page {page}: {new_ips} new IP addresses saved.")
                        else:
                            self.logger.info(f"Page {page}: No IP addresses found.")
                    else:
                        self.logger.warning(f"Unable to fetch page {page}.")
                    time.sleep(5)
                except Exception as e:
                    self.logger.error(f"Error processing page {page}: {str(e)}")
                    continue
                    
            self.logger.info("Collection completed.")
            
        except Exception as e:
            self.logger.error(f"Collection error: {str(e)}")