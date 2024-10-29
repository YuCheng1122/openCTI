from config import Config
import logging
import os
import time
import random
import mysql.connector
import json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By


class VirusTotalCollector:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        
        # 設置截圖目錄
        self.error_screenshots_dir = os.path.join(
            self.config.path.logs_dir, 
            'virustotal_screenshots'
        )
        os.makedirs(self.error_screenshots_dir, exist_ok=True)
        
        # 設置數據庫配置
        self.setup_database()
        
        # 設置 cookies - 直接從配置文件獲取
        self.vt_cookies = {
            '__gsas': self.config.virus_total.gsas,
            '__utma': self.config.virus_total.utma,
            '__utmz': self.config.virus_total.utmz,
            '_ga': self.config.virus_total.ga,
            '_ga_1R8YHMJVFG': self.config.virus_total.ga_1r8yhmjvfg,
            '_ga_BLNDV9X2JR': self.config.virus_total.ga_blndv9x2jr,
            '_ga_E8LNX6HSCN': self.config.virus_total.ga_e8lnx6hscn,
            '_gid': self.config.virus_total.gid,
            'new-privacy-policy-accepted': self.config.virus_total.new_privacy_policy_accepted
        }

        # 初始化 webdriver
        try:
            self.setup_webdriver()
            self.logger.info("VirusTotal collector initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize VirusTotal collector: {str(e)}")
            raise

    def setup_database(self):
        """設置數據庫配置"""
        try:
            self.db_config = {
                'host': self.config.mysql.host,
                'user': self.config.mysql.user,
                'password': self.config.mysql.password,
                'database': self.config.mysql.database,
                'port': self.config.mysql.port
            }
            self.logger.info("Database configuration setup successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup database configuration: {str(e)}")
            raise
    
    def setup_database(self):
        """設置數據庫配置"""
        try:
            self.db_config = {
                'host': self.config.mysql.host,
                'user': self.config.mysql.user,
                'password': self.config.mysql.password,
                'database': self.config.mysql.database,
                'port': self.config.mysql.port
            }
            self.logger.info("Database configuration setup successfully")
        except Exception as e:
            self.logger.error(f"Failed to setup database configuration: {str(e)}")
            raise

    def get_ip_from_db(self):
        """Get an IP address from the database that needs to be updated."""
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor(dictionary=True)
            
            query = """
            SELECT a.ip_address 
            FROM AbuseIPDB_IP_Report a
            LEFT JOIN VirusTotal_IP_Info v ON a.ip_address = v.ip_address
            WHERE v.ip_address IS NULL OR v.update_time < DATE_SUB(NOW(), INTERVAL 1 DAY)
            ORDER BY a.score DESC
            LIMIT 1
            """
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                return result['ip_address']
            else:
                return None
        except mysql.connector.Error as err:
            logging.error(f"Database error: {err}")
            return None
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def update_db(self, ip, data):
        """Update the database with the scraped data."""
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            
            query = """
            INSERT INTO VirusTotal_IP_Info 
            (ip_address, positive_detections, total_detections, country, 
            total_communicating_files, jarm_fingerprint, engine_detections) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            positive_detections = VALUES(positive_detections),
            total_detections = VALUES(total_detections),
            country = VALUES(country),
            total_communicating_files = VALUES(total_communicating_files),
            jarm_fingerprint = VALUES(jarm_fingerprint),
            engine_detections = VALUES(engine_detections),
            update_time = CURRENT_TIMESTAMP
            """
            
            engine_detections = {engine['engine']: engine['status'] for engine in data['engines']}
            
            values = (
                ip,
                data['positive'],
                data['total'],
                data['country'],
                data['total_files'],
                data['jarm'],
                json.dumps(engine_detections)
            )
            
            cursor.execute(query, values)
            conn.commit()
            
            logging.info(f"Updated database for IP: {ip}")
        except mysql.connector.Error as err:
            logging.error(f"Database error: {err}")
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def setup_logging(self):
        """Set up logging to file."""
        log_dir = "/home/ubuntu/threat_intelligence_v2/log"
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(log_dir, "virustotal_scraper.log"),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_screenshot_dir(self):
        """Set up directory for error screenshots."""
        self.error_screenshots_dir = "/home/ubuntu/threat_intelligence_v2/error_screenshots"
        os.makedirs(self.error_screenshots_dir, exist_ok=True)

    def setup_webdriver(self):
        """Set up Chrome WebDriver with temporary profile directory"""
        try:
            # 建立臨時目錄
            temp_dir = "/tmp/chrome-temp"
            os.makedirs(temp_dir, exist_ok=True)
            self.logger.info(f"Created temporary Chrome profile directory: {temp_dir}")

            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument(f'--user-data-dir={temp_dir}')
            
            service = ChromeService(executable_path=ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)

            # 先訪問網站
            self.driver.get('https://www.virustotal.com')
            time.sleep(2)

            # 添加 cookies 時進行名稱轉換
            cookie_mapping = {
                'gsas': '__gsas',
                'utma': '__utma',
                'utmz': '__utmz',
                'ga': '_ga',
                'ga_1r8yhmjvfg': '_ga_1R8YHMJVFG',
                'ga_blndv9x2jr': '_ga_BLNDV9X2JR',
                'ga_e8lnx6hscn': '_ga_E8LNX6HSCN',
                'gid': '_gid',
                'new_privacy_policy_accepted': 'new-privacy-policy-accepted'
            }

            for config_name, cookie_name in cookie_mapping.items():
                value = getattr(self.config.virus_total, config_name)
                if value:
                    self.driver.add_cookie({
                        'name': cookie_name,
                        'value': value,
                        'domain': '.virustotal.com'
                    })
                    self.logger.debug(f"Added cookie: {cookie_name}")
            
            self.logger.info("WebDriver setup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to setup WebDriver: {str(e)}")
            raise

    def wait_for_element_with_js(self, js, timeout=30, poll_frequency=0.5):
        """Wait for an element to be present using JavaScript."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.driver.execute_script(js)
            if result is not None and not result.startswith('Error'):
                return result
            time.sleep(poll_frequency)
        return None

    def take_screenshot(self, ip):
        """Take a screenshot and save it with the IP in the filename."""
        filename = f"virustotal_error_{ip}.png"
        filepath = os.path.join(self.error_screenshots_dir, filename)
        self.driver.save_screenshot(filepath)

    def execute_js_with_error_handling(self, js, description):
        """Execute JavaScript with error handling."""
        try:
            result = self.driver.execute_script(js)
            if result and not result.startswith('Error'):
                return result
            else:
                return None
        except Exception:
            return None

    def collect_continuous(self):
        """持續運行的收集模式"""
        self.running = True
        while self.running:
            try:
                # 重新設置 driver 和數據庫連接
                if not hasattr(self, 'driver') or not self.driver:
                    self.setup_webdriver()
                
                self.logger.info("Starting continuous collection cycle")
                ip = self.get_ip_from_db()
                
                if not ip:
                    self.logger.info("No new IPs to process, waiting before next cycle")
                    time.sleep(300)  # 5 分鐘
                    continue
                
                self.logger.info(f"Scraping VirusTotal for IP: {ip}")
                result = self.scrape(ip)
                if result:
                    self.update_db(ip, result)
                    self.logger.info(f"Successfully updated information for IP: {ip}")
                    time.sleep(random.randint(30, 40))  # 随機延遲 30-40 秒
                else:
                    self.logger.error(f"Failed to retrieve information for IP: {ip}")
                    time.sleep(60)  # 錯誤後等待 1 分鐘
                
            except Exception as e:
                self.logger.error(f"Error in collection cycle: {str(e)}")
                # 關閉當前資源
                if hasattr(self, 'driver') and self.driver:
                    try:
                        self.driver.quit()
                    except:
                        pass
                    self.driver = None
                time.sleep(60)  # 錯誤後等待 1 分鐘
    
    def stop_collection(self):
        """停止持續收集"""
        self.running = False
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

    def collect(self):
        """執行單次收集過程"""
        try:
            self.logger.info("Starting VirusTotal data collection")
            while True:
                ip = self.get_ip_from_db()
                if not ip:
                    self.logger.info("No IP addresses to update")
                    break
                
                self.logger.info(f"Scraping VirusTotal for IP: {ip}")
                result = self.scrape(ip)
                if result:
                    self.update_db(ip, result)
                    self.logger.info(f"Successfully updated information for IP: {ip}")
                else:
                    self.logger.error(f"Failed to retrieve information for IP: {ip}")
                
                time.sleep(random.randint(30, 40))
                
        except Exception as e:
            self.logger.error(f"Collection error: {str(e)}")
        finally:
            self.close()
    
    @staticmethod
    def convert_formatted_number(formatted_number):
        """Convert a formatted number string to an integer."""
        if 'K' in formatted_number:
            return int(float(formatted_number.replace('K', '').replace(' ', '')) * 1000)
        elif 'M' in formatted_number:
            return int(float(formatted_number.replace('M', '').replace(' ', '')) * 1000000)
        else:
            return int(formatted_number.replace(' ', ''))

    def get_engine_data(self, total):
        """Get detection data from various engines."""
        engines = []
        for i in range(total):
            engine_js = f"""
            try {{
                let view = document.querySelector("#view-container > ip-address-view");
                if (!view) return 'Error: IP address view not found';
                let detectionList = view.shadowRoot.querySelector("#detection > vt-ui-detections-list");
                if (!detectionList) return 'Error: Detection list not found';
                let engine = detectionList.shadowRoot.querySelector("#engine-{i}");
                if (!engine) return 'Error: Engine element not found';
                return engine.textContent.trim();
            }} catch (e) {{
                return 'Error: ' + e.message;
            }}
            """
            detection_js = f"""
            try {{
                let view = document.querySelector("#view-container > ip-address-view");
                if (!view) return 'Error: IP address view not found';
                let detectionList = view.shadowRoot.querySelector("#detection > vt-ui-detections-list");
                if (!detectionList) return 'Error: Detection list not found';
                let engineText = detectionList.shadowRoot.querySelector("#engine-text-{i} > span");
                if (!engineText) return 'Error: Engine text element not found';
                return engineText.textContent.trim();
            }} catch (e) {{
                return 'Error: ' + e.message;
            }}
            """
            engine_name = self.execute_js_with_error_handling(engine_js, f"engine name {i}")
            detection_status = self.execute_js_with_error_handling(detection_js, f"detection status {i}")
            if engine_name and detection_status:
                engines.append({'engine': engine_name, 'status': detection_status})
        return engines

    def get_relations(self, total_files_to_fetch):
        """Get relation data for communicating files."""
        relations = []
        for i in range(1, total_files_to_fetch + 1):
            relation_js = f"""
            try {{
                let view = document.querySelector("#view-container > ip-address-view");
                if (!view) return 'Error: IP address view not found';
                let relations = view.shadowRoot.querySelector("#relations");
                if (!relations) return 'Error: Relations not found';
                let communicating = relations.shadowRoot.querySelector("#communicating");
                if (!communicating) return 'Error: Communicating section not found';
                let row = communicating.shadowRoot.querySelector("div > table > tbody > tr:nth-child({i})");
                if (!row) return 'Error: Row not found';
                return row.textContent.trim();
            }} catch (e) {{
                return 'Error: ' + e.message;
            }}
            """
            detection_ratio_js = f"""
            try {{
                let view = document.querySelector("#view-container > ip-address-view");
                if (!view) return 'Error: IP address view not found';
                let relations = view.shadowRoot.querySelector("#relations");
                if (!relations) return 'Error: Relations not found';
                let communicating = relations.shadowRoot.querySelector("#communicating");
                if (!communicating) return 'Error: Communicating section not found';
                let ratio = communicating.shadowRoot.querySelector("div > table > tbody > tr:nth-child({i}) > td:nth-child(2) > vt-ui-detections-ratio");
                if (!ratio) return 'Error: Ratio element not found';
                let number = ratio.shadowRoot.querySelector("div.number");
                let total = ratio.shadowRoot.querySelector("div.total");
                if (!number || !total) return 'Error: Number or total element not found';
                return number.textContent.trim() + ' ' + total.textContent.trim();
            }} catch (e) {{
                return 'Error: ' + e.message;
            }}
            """
            relation = self.execute_js_with_error_handling(relation_js, f"relation {i}")
            detection_ratio = self.execute_js_with_error_handling(detection_ratio_js, f"detection ratio {i}")
            if relation and detection_ratio:
                relations.append({'relation': relation, 'detection_ratio': detection_ratio})
        return relations

    def handle_robot_checkpoint(self):
        """Handle robot checkpoint if encountered."""
        try:
            # Wait for the checkbox to be clickable
            checkbox = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, ".recaptcha-checkbox-border"))
            )
            checkbox.click()
            
            # Wait for the checkpoint to be solved
            WebDriverWait(self.driver, 60).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "vt-ui-shell"))
            )
            logging.info("Robot checkpoint solved successfully.")
            return True
        except (TimeoutException, NoSuchElementException):
            logging.error("Failed to solve robot checkpoint.")
            return False

    def handle_captcha(self):
        """Handle CAPTCHA in a human-like manner."""
        try:
            logging.info("Attempting to solve CAPTCHA with human-like behavior...")
            
            # Wait for the iframe to be present with a random delay
            time.sleep(random.uniform(2, 4))
            iframe = WebDriverWait(self.driver, 20).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "iframe[title^='reCAPTCHA']"))
            )
            
            # Switch to the iframe
            self.driver.switch_to.frame(iframe)
            
            # Wait for the checkbox to be clickable
            checkbox = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, ".recaptcha-checkbox-border"))
            )
            
            # Move the mouse to the checkbox in a human-like manner
            action = ActionChains(self.driver)
            action.move_to_element_with_offset(checkbox, random.randint(-5, 5), random.randint(-5, 5))
            action.pause(random.uniform(0.1, 0.3))
            action.move_to_element(checkbox)
            action.pause(random.uniform(0.1, 0.3))
            
            # Click the checkbox
            action.click()
            action.perform()
            
            # Random delay after clicking
            time.sleep(random.uniform(0.5, 1.5))
            
            # Switch back to the main content
            self.driver.switch_to.default_content()
            
            # Wait for the page to load with a random delay
            time.sleep(random.uniform(2, 4))
            WebDriverWait(self.driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'vt-ui-shell'))
            )
            
            logging.info("CAPTCHA potentially solved with human-like behavior.")
            return True
        except Exception as e:
            logging.error(f"Failed to solve CAPTCHA automatically: {str(e)}")
            self.take_screenshot("captcha_failure")
            
            # Fall back to manual solving
            print("Automatic CAPTCHA solving failed. Please solve it manually in the browser.")
            input("Press Enter after solving...")
            
            try:
                WebDriverWait(self.driver, 30).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'vt-ui-shell'))
                )
                logging.info("CAPTCHA solved manually successfully.")
                return True
            except TimeoutException:
                logging.error("Page did not load after CAPTCHA was solved.")
                return False
    
    def scrape(self, ip):
        """Scrape VirusTotal for information about the given IP in a human-like manner."""
        logging.info(f"Scraping VirusTotal for IP: {ip}")
        vt_url = f'https://www.virustotal.com/gui/ip-address/{ip}'
        self.driver.get(vt_url)
        
        # Random delay after page load
        time.sleep(random.uniform(3, 5))

        try:
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'vt-ui-shell'))
            )
        except TimeoutException:
            # If vt-ui-shell is not found, check for CAPTCHA
            if "captcha" in self.driver.page_source.lower():
                if not self.handle_captcha():
                    self.take_screenshot(ip)
                    return None
            else:
                logging.error("Page did not load as expected and no CAPTCHA detected.")
                self.take_screenshot(ip)
                return None

        # Simulate human-like scrolling
        self.human_like_scroll()

        # Define the order of data extraction
        data_extraction_order = ['positive', 'total', 'country', 'engines', 'total_files', 'jarm', 'relations']
        random.shuffle(data_extraction_order)  # Randomize the order

        result = {}
        for data_type in data_extraction_order:
            # Random delay between data extractions
            time.sleep(random.uniform(1, 3))
            
            if data_type == 'positive':
                result['positive'] = self.extract_positive()
            elif data_type == 'total':
                result['total'] = self.extract_total()
            elif data_type == 'country':
                result['country'] = self.extract_country()
            elif data_type == 'engines':
                result['engines'] = self.extract_engines()
            elif data_type == 'total_files':
                result['total_files'] = self.extract_total_files()
            elif data_type == 'jarm':
                result['jarm'] = self.extract_jarm()
            elif data_type == 'relations':
                result['relations'] = self.extract_relations()

        return result

    def human_like_scroll(self):
        """Simulate human-like scrolling behavior."""
        total_height = self.driver.execute_script("return document.body.scrollHeight")
        viewport_height = self.driver.execute_script("return window.innerHeight")
        scrolls = random.randint(3, 6)  # Random number of scroll actions
        
        for _ in range(scrolls):
            target_scroll = random.uniform(0, total_height - viewport_height)
            self.driver.execute_script(f"window.scrollTo(0, {target_scroll});")
            time.sleep(random.uniform(0.5, 2))  # Random pause between scrolls

    def extract_positive(self):
        positive = self.wait_for_element_with_js(self.positive_js)
        return int(positive) if positive and positive.isdigit() else None

    def extract_total(self):
        total = self.wait_for_element_with_js(self.total_js)
        try:
            return int(total.split('/')[-1].strip()) if total else None
        except (ValueError, IndexError, AttributeError):
            return None

    def extract_country(self):
        return self.execute_js_with_error_handling(self.country_js, "country")

    def extract_engines(self):
        total = self.extract_total()
        return self.get_engine_data(total) if total else []

    def extract_total_files(self):
        total_files = self.execute_js_with_error_handling(self.total_files_js, "total communicating files")
        if total_files and not total_files.startswith('Error'):
            return self.convert_formatted_number(total_files.strip('()'))
        return 0

    def extract_jarm(self):
        return self.execute_js_with_error_handling(self.jarm_js, "JARM fingerprint")

    def extract_relations(self):
        total_files = self.extract_total_files()
        total_files_to_fetch = min(total_files, 10)
        return self.get_relations(total_files_to_fetch)

    def close(self):
        """Close the WebDriver."""
        self.driver.quit()

    # JavaScript snippets
    positive_js = """
    try {
        let view = document.querySelector("#view-container > ip-address-view");
        if (!view) return 'Error: IP address view not found';
        let report = view.shadowRoot.querySelector("#report");
        if (!report) return 'Error: Report not found';
        let widget = report.shadowRoot.querySelector("div > div.row.mb-4.d-none.d-lg-flex > div.col-auto > vt-ioc-score-widget");
        if (!widget) return 'Error: Score widget not found';
        let chart = widget.shadowRoot.querySelector("div > vt-ioc-score-widget-detections-chart");
        if (!chart) return 'Error: Detections chart not found';
        let positives = chart.shadowRoot.querySelector("#positives");
        if (!positives) return 'Error: Positives element not found';
        return positives.textContent.trim();
    } catch (e) {
        return 'Error: ' + e.message;
    }
    """

    total_js = """
    try {
        let view = document.querySelector("#view-container > ip-address-view");
        if (!view) return 'Error: IP address view not found';
        let report = view.shadowRoot.querySelector("#report");
        if (!report) return 'Error: Report not found';
        let widget = report.shadowRoot.querySelector("div > div.row.mb-4.d-none.d-lg-flex > div.col-auto > vt-ioc-score-widget");
        if (!widget) return 'Error: Score widget not found';
        let chart = widget.shadowRoot.querySelector("div > vt-ioc-score-widget-detections-chart");
        if (!chart) return 'Error: Detections chart not found';
        let total = chart.shadowRoot.querySelector("div > div > div:nth-child(2)");
        if (!total) return 'Error: Total element not found';
        return total.textContent.trim();
    } catch (e) {
        return 'Error: ' + e.message;
    }
    """

    country_js = """
    try {
        let view = document.querySelector('#view-container > ip-address-view');
        if (!view) return 'Error: IP address view not found';
        let report = view.shadowRoot.querySelector('#report > vt-ui-ip-card');
        if (!report) return 'Error: IP card not found';
        let country = report.shadowRoot.querySelector('#country');
        if (!country) return 'Error: Country element not found';
        return country.textContent.trim();
    } catch (e) {
        return 'Error: ' + e.message;
    }
    """

    total_files_js = """
    try {
        let view = document.querySelector("#view-container > ip-address-view");
        if (!view) return 'Error: IP address view not found';
        let relations = view.shadowRoot.querySelector("#relations");
        if (!relations) return 'Error: Relations not found';
        let files = relations.shadowRoot.querySelector("div > vt-ui-expandable.mb-3.communicating_files");
        if (!files) return 'Error: Communicating files section not found';
        let badge = files.shadowRoot.querySelector("#info-badge");
        if (!badge) return 'Error: Info badge not found';
        return badge.textContent.trim();
    } catch (e) {
        return 'Error: ' + e.message;
    }
    """

    jarm_js = """
    try {
        let view = document.querySelector("#view-container > ip-address-view");
        if (!view) return 'Error: IP address view not found';
        let report = view.shadowRoot.querySelector("#report");
        if (!report) return 'Error: Report not found';
        let expandable = report.querySelector("span:nth-child(4) > div > vt-ui-expandable:nth-child(2)");
        if (!expandable) return 'Error: Expandable section not found';
        let entry = expandable.querySelector("span > vt-ui-expandable-entry:nth-child(1) > span > div");
        if (!entry) return 'Error: JARM entry not found';
        return entry.textContent.trim();
    } catch (e) {
        return 'Error: ' + e.message;
    }
    """

    def collect(self):
        """執行收集過程"""
        try:
            while True:
                ip = self.get_ip_from_db()
                if not ip:
                    self.logger.info("No IP addresses to update")
                    break
                
                self.logger.info(f"Scraping VirusTotal for IP: {ip}")
                result = self.scrape(ip)
                if result:
                    self.update_db(ip, result)
                    self.logger.info(f"Successfully updated information for IP: {ip}")
                else:
                    self.logger.error(f"Failed to retrieve information for IP: {ip}")
                
                # 使用配置中的延遲範圍
                delay = random.randint(*self.config.virustotal.request_delay)
                time.sleep(delay)
                
        except Exception as e:
            self.logger.error(f"Collection error: {str(e)}")
        finally:
            self.close()
            
