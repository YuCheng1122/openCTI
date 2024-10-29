# collectors/phishing_data_collector.py

import mysql.connector
import logging
from datetime import datetime
import os
from typing import List, Tuple, Optional
from config import Config

class PhishingDataCollector:
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

    def query_today_records(self) -> List[Tuple[str, str]]:
        """查詢今天的記錄"""
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()

            today = datetime.today().strftime('%Y-%m-%d')
            query = '''
            SELECT phishing_url, ip
            FROM phishing_data
            WHERE DATE(timestamp) = %s
            '''
            cursor.execute(query, (today,))

            results = cursor.fetchall()
            self.logger.info(f"Retrieved {len(results)} records for {today}")
            return results

        except mysql.connector.Error as e:
            self.logger.error(f"Failed to query the database: {e}")
            return []
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def save_to_txt(self, records: List[Tuple[str, str]], filename: str) -> None:
        """保存記錄到文本文件"""
        try:
            with open(filename, 'w') as file:
                for record in records:
                    phishing_url, ip = record
                    if phishing_url and ip:
                        file.write(f"URL: {phishing_url}, IP: {ip}\n")
            self.logger.info(f"Records saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save records to file: {e}")
            raise

    def collect(self) -> None:
        """執行收集過程"""
        try:
            self.logger.info("Starting phishing data collection")
            records = self.query_today_records()
            
            if records:
                # 創建日期目錄
                today = datetime.now().strftime('%Y-%m-%d')
                daily_dir = os.path.join(self.config.path.phishing_data_dir, today)
                os.makedirs(daily_dir, exist_ok=True)

                # 創建輸出文件
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = os.path.join(daily_dir, f"{timestamp}_phishing_cti.txt")
                
                self.save_to_txt(records, filename)
                self.logger.info("Phishing data collection completed successfully")
            else:
                self.logger.info("No records found for today")

        except Exception as e:
            self.logger.error(f"Failed to collect phishing data: {e}")
            raise