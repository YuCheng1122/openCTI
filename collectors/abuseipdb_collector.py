import mysql.connector
from mysql.connector import Error
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium_stealth import stealth
from webdriver_manager.chrome import ChromeDriverManager
import json
import os
import re
import random
import time
from datetime import datetime
from typing import List
from config import Config

class AbuseIPDBCollector:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.invalid_ip_pattern = re.compile(
            r'^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|224\.|240\.)'
        )
        
        # 設置 cookies
        self.cookies = {
            'abuseipdb_session': self.config.abuseipdb.session,
            'env': self.config.abuseipdb.env,
            'XSRF-TOKEN': self.config.abuseipdb.xsrf_token,
            'cf_clearance': self.config.abuseipdb.cf_clearance
        }
        
        # 設置截圖目錄
        self.screenshot_folder = os.path.join(self.config.path.base_dir, "error_screenshots")
        os.makedirs(self.screenshot_folder, exist_ok=True)

        try:
            self.setup_driver()
            self.setup_database()
            self.logger.info("AbuseIPDB collector initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize AbuseIPDB collector: {str(e)}")
            raise
    
    def collect_continuous(self):
        """持續運行的收集模式"""
        self.running = True
        while self.running:
            try:    
                # 重新設置 driver 和數據庫連接
                if not hasattr(self, 'driver') or not hasattr(self, 'conn'):
                    self.setup_driver()
                    self.setup_database()
                    self.add_cookies()

                self.logger.info("Starting continuous collection cycle")
                results = self.scrape_ips(self.config.abuseipdb.batch_size)
                
                if not results:
                    self.logger.info("No new IPs to process, waiting before next cycle")
                    time.sleep(300)  # 5 分鐘
                else:
                    self.logger.info(f"Processed {len(results)} IPs in this cycle")
                    time.sleep(30)  # 30 秒
                
            except Exception as e:
                self.logger.error(f"Error in collection cycle: {str(e)}")
                # 關閉當前資源
                self.close()
                time.sleep(60)  # 錯誤後等待 1 分鐘
    
    def stop_collection(self):
        """停止持續收集"""
        self.running = False

    def setup_driver(self):
        """設置 Selenium WebDriver"""
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        
        user_agent = self.get_random_user_agent()
        options.add_argument(f'user-agent={user_agent}')

        self.driver = webdriver.Chrome(service=service, options=options)
        stealth(self.driver,
               languages=["en-US", "en"],
               vendor="Google Inc.",
               platform="Win32",
               webgl_vendor="Intel Inc.",
               renderer="Intel Iris OpenGL Engine",
               fix_hairline=True)
        
    def setup_database(self):
        """設置數據庫連接"""
        try:
            self.conn = mysql.connector.connect(
                host=self.config.mysql.host,
                user=self.config.mysql.user,
                password=self.config.mysql.password,
                database=self.config.mysql.database,
                port=self.config.mysql.port
            )
            self.cur = self.conn.cursor()
            self.logger.info("Database connection established successfully")
        except mysql.connector.Error as e:
            self.logger.error(f"MySQL connection error: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during database setup: {str(e)}")
            raise

    def get_random_user_agent(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
        ]
        return random.choice(user_agents)
    
    def add_cookies(self):
        self.driver.get("https://www.abuseipdb.com")
        for name, value in self.cookies.items():
            if value:  # Only add the cookie if it has a value
                self.driver.add_cookie({'name': name, 'value': value})
        self.driver.refresh()

    def is_valid_public_ip(self, ip):
        return not self.invalid_ip_pattern.match(ip)

    def get_ips_to_scrape(self, batch_size: int = 100) -> List[str]:
        """
        從數據庫獲取需要抓取的 IP 地址
        """
        try:
            # 確保數據庫連接有效
            self.ensure_db_connection()
            
            # 檢查 Invalid_IPs 表是否存在，如果不存在則創建
            check_table = """
            CREATE TABLE IF NOT EXISTS Invalid_IPs (
                ip_address VARCHAR(45) PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
            """
            self.cur.execute(check_table)
            self.conn.commit()
            
            # 使用改進的查詢
            query = """
            WITH RankedIPs AS (
                SELECT 
                    ip_address,
                    score
                FROM Combined_IP_Score cis
                WHERE NOT EXISTS (
                    SELECT 1 
                    FROM AbuseIPDB_IP_Report air
                    WHERE air.ip_address = cis.ip_address
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM Invalid_IPs inv
                    WHERE inv.ip_address = cis.ip_address
                )
                ORDER BY score DESC
                LIMIT %s
            )
            SELECT ip_address FROM RankedIPs;
            """
            
            self.cur.execute(query, (batch_size,))
            results = self.cur.fetchall()
            
            valid_ips = [row[0] for row in results if self.is_valid_public_ip(row[0])]
            
            self.logger.info(f"Retrieved {len(valid_ips)} valid IPs to process")
            return valid_ips
            
        except mysql.connector.Error as e:
            self.logger.error(f"Database error while fetching IPs: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error while fetching IPs: {str(e)}")
            return []

    def ensure_db_connection(self):
        """確保數據庫連接有效"""
        try:
            self.conn.ping(reconnect=True, attempts=3, delay=5)
        except mysql.connector.Error as e:
            self.logger.error(f"Database connection error: {str(e)}")
            self.setup_database()
    
    def scrape_ip_data(self, ip):
        url = f"https://www.abuseipdb.com/check/{ip}"
        self.driver.get(url)
        
        try:
            # Wait for the main content to load
            WebDriverWait(self.driver, self.config.abuseipdb.request_time).until(
                EC.presence_of_element_located((By.ID, "report-wrapper"))
            )
            
            # Extract data using JS path selectors
            isp = self.driver.execute_script(
                'return document.querySelector("#report-wrapper > div:nth-child(1) > div:nth-child(1) > div > table > tbody > tr:nth-child(1) > td").textContent'
            )
            
            score = self.driver.execute_script(
                'return document.querySelector("#report-wrapper > div:nth-child(1) > div:nth-child(1) > div > p:nth-child(2) > b:nth-child(2)").textContent'
            )
            score = int(score.replace('%', ''))
            
            country = self.driver.execute_script(
                'return document.querySelector("#report-wrapper > div:nth-child(1) > div:nth-child(1) > div > table > tbody > tr:nth-child(4) > td").textContent'
            )
            
            label_script = '''
                var element = document.querySelector("#reports > tbody > tr:nth-child(1) > td.text-right > span:nth-child(1)");
                return element ? element.textContent : "";
            '''
            label = self.driver.execute_script(label_script)
            
            self.logger.debug(f"Scraped data for IP {ip}: ISP={isp}, Score={score}, Country={country}, Label={label}")
            
            return {
                "ip": ip,
                "isp": isp.strip(),
                "score": score,
                "country": country.strip(),
                "label": label.strip() if label else None,  
                "update_time": datetime.now().isoformat()
            }
        except Exception as e:
            if "TimeoutException" in str(e):
                self.logger.error(f"Cookie expiration or Cloudflare challenge detected for IP {ip}. Please update your cookies.")
            else:
                self.logger.error(f"Error scraping data for IP {ip}: {str(e)}")
            
            screenshot_path = os.path.join(self.screenshot_folder, f"error_{ip}.png")
            if not os.path.exists(screenshot_path):
                self.driver.save_screenshot(screenshot_path)
                self.logger.info(f"Screenshot saved to {screenshot_path}")
            else:
                self.logger.info(f"Screenshot already exists for IP {ip}")
            self.mark_ip_as_invalid(ip)
            return None
        
    def mark_ip_as_invalid(self, ip):
        try:
            self.cur.execute("""
                INSERT INTO Invalid_IPs (ip_address) VALUES (%s)
                ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address)
            """, (ip,))
            self.conn.commit()
            self.logger.info(f"Marked IP {ip} as invalid")
        except Error as e:
            self.logger.error(f"Error marking IP {ip} as invalid: {str(e)}")
            self.conn.rollback()    

    def insert_data(self, data):
        try:
            # Ensure label is valid JSON
            if isinstance(data['label'], str):
                try:
                    json_label = json.dumps(data['label'])
                except json.JSONDecodeError:
                    json_label = json.dumps({"value": data['label']})
            elif isinstance(data['label'], dict):
                json_label = json.dumps(data['label'])
            else:
                json_label = json.dumps({"value": str(data['label'])})

            self.cur.execute("""
                INSERT INTO AbuseIPDB_IP_Report (ip_address, isp, country, score, label, update_time)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    isp = VALUES(isp),
                    country = VALUES(country),
                    score = VALUES(score),
                    label = VALUES(label),
                    update_time = VALUES(update_time)
            """, (data['ip'], data['isp'], data['country'], data['score'], json_label, data['update_time']))
            self.conn.commit()
            self.logger.debug(f"Data inserted/updated for IP {data['ip']}")
        except Error as e:
            self.logger.error(f"Database insertion error for IP {data['ip']}: {str(e)}")
            self.conn.rollback()
            
    def scrape_ips(self, batch_size=100):
        self.add_cookies()
        results = []
        while True:
            ip_list = self.get_ips_to_scrape(batch_size)
            if not ip_list:
                self.logger.info("No more valid IPs to scrape. Exiting.")
                break

            self.logger.info(f"Retrieved {len(ip_list)} valid public IPs to scrape")
            
            for ip in ip_list:
                self.logger.info(f"Scraping data for IP: {ip}")
                data = self.scrape_ip_data(ip)
                if data:
                    self.insert_data(data)
                    results.append(data)
                time.sleep(random.uniform(5, 10))  
            
            self.logger.info(f"Completed batch of {len(ip_list)} IPs")

        return results
    
    def collect(self) -> None:
        """執行收集過程"""
        try:
            self.logger.info("Starting AbuseIPDB data collection")
            self.add_cookies()
            results = self.scrape_ips()
            self.logger.info(f"Successfully collected data for {len(results)} IPs")
        except Exception as e:
            self.logger.error(f"AbuseIPDB collection failed: {str(e)}")
        finally:
            self.close()

    def close(self):
        """關閉資源"""
        if hasattr(self, 'driver'):
            self.driver.quit()
        if hasattr(self, 'cur'):
            self.cur.close()
        if hasattr(self, 'conn'):
            self.conn.close()
