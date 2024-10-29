import requests
from bs4 import BeautifulSoup
import mysql.connector
from dns import resolver, exception
from datetime import datetime
import logging
from typing import List, Tuple, Optional
from config import Config

class PhishingCollector:
    def __init__(self, config: Config):
        self.config = config
        
        self.logger = logging.getLogger(__name__)
        self.db_config = {
            'host': config.mysql.host,
            'user': config.mysql.user,
            'password': config.mysql.password,
            'database': config.mysql.database,
            'port': config.mysql.port
        }

    def extract_data(self) -> List[Tuple[str, str, Optional[str]]]:
        """從 OpenPhish 網站提取數據"""
        url = "https://openphish.com/"
        data = []
        
        try:
            response = requests.get(url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            tbody = soup.select_one('#wrap > div > table > tbody')

            if tbody:
                rows = tbody.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) == 3:
                        phishing_url = cells[0].text.strip()
                        targeted_brand = cells[1].text.strip()
                        ip = self._get_domain_ip(phishing_url)
                        data.append((phishing_url, targeted_brand, ip))
            
            self.logger.info(f"Successfully extracted {len(data)} phishing URLs")
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to extract data: {str(e)}")
            return []

    def _get_domain_ip(self, url: str) -> Optional[str]:
        """獲取域名的 IP 地址"""
        try:
            domain = url.split('//')[-1].split('/')[0]
            answers = resolver.resolve(domain, 'A')
            return answers[0].to_text()
        except Exception as e:
            self.logger.warning(f"Failed to resolve IP for {url}: {str(e)}")
            return None

    def save_to_db(self, data: List[Tuple[str, str, Optional[str]]]) -> None:
        """保存數據到數據庫"""
        if not data:
            self.logger.info("No data to save")
            return

        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()

            # 先檢查每個 URL 是否已存在
            check_sql = "SELECT phishing_url FROM phishing_data WHERE phishing_url = %s"
            
            # 準備插入的數據
            insert_sql = '''
            INSERT INTO phishing_data (phishing_url, targeted_brand, ip)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
                targeted_brand = VALUES(targeted_brand),
                ip = VALUES(ip);
            '''
            
            new_records = 0
            updated_records = 0
            skipped_records = 0
            
            for row in data:
                phishing_url, targeted_brand, ip = row
                
                # 檢查 URL 是否已存在
                cursor.execute(check_sql, (phishing_url,))
                exists = cursor.fetchone()
            
                if ip:  # 只處理有 IP 的記錄
                    try:
                        cursor.execute(insert_sql, row)
                        if exists:
                            updated_records += 1
                        else:
                            new_records += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to save record {row}: {str(e)}")
                        skipped_records += 1
                else:
                    skipped_records += 1

            conn.commit()
            self.logger.info(f"Database operation completed:")
            self.logger.info(f"- Total records processed: {len(data)}")
            self.logger.info(f"- New records added: {new_records}")
            self.logger.info(f"- Records updated: {updated_records}")
            self.logger.info(f"- Records skipped: {skipped_records}")
            
        except Exception as e:
            self.logger.error(f"Database operation failed: {str(e)}")
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def collect(self) -> None:
        """執行收集過程"""
        try:
            self.logger.info("Starting phishing data collection")
            data = self.extract_data()
            if data:
                self.save_to_db(data)
            self.logger.info("Phishing data collection completed")
        except Exception as e:
            self.logger.error(f"Phishing collection failed: {str(e)}")