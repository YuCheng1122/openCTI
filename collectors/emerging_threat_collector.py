import os
import requests
from bs4 import BeautifulSoup
import logging
from typing import List
from config import Config

class EmergingThreatCollector:
    """Emerging Threat 規則收集器"""
    def __init__(self, config: Config):
        self.config = config
        self.base_url = config.emerging_threat.base_url
        self.max_size = config.emerging_threat.max_file_size_kb

    def collect(self) -> None:
        """收集規則文件"""
        try:
            output_dir = self.config.path.get_daily_folder(self.config.path.rules_dir)
            os.makedirs(output_dir, exist_ok=True)
            
            content = self._fetch_website_content()
            soup = BeautifulSoup(content, "html.parser")
            self._parse_and_download_files(soup, output_dir)
            
            logging.info("Rules download completed successfully")
        except Exception as e:
            logging.error(f"Failed to collect rules: {e}")

    def _fetch_website_content(self) -> str:
        """獲取網站內容"""
        response = requests.get(self.base_url)
        response.raise_for_status()
        return response.content

    def _parse_and_download_files(self, soup: BeautifulSoup, output_dir: str) -> None:
        """解析並下載規則文件"""
        for row in soup.find_all("tr"):
            columns = row.find_all("td")
            if len(columns) <= 2:
                continue

            file_link = columns[0].find("a")
            if not file_link:
                continue

            file_name = file_link.text.strip()
            if not file_name.endswith('.rules'):
                continue

            file_size = self._convert_size_to_kb(columns[2].text.strip())
            if file_size > self.max_size:
                continue

            self._download_file(
                self.base_url + file_link.get("href"),
                output_dir,
                file_name
            )

    def _convert_size_to_kb(self, size_str: str) -> float:
        """轉換文件大小到 KB"""
        if 'MB' in size_str:
            return float(size_str.replace('MB', '').strip()) * 1024
        elif 'KB' in size_str:
            return float(size_str.replace('KB', '').strip())
        return 0

    def _download_file(self, url: str, output_dir: str, filename: str) -> None:
        """下載單個文件"""
        file_path = os.path.join(output_dir, filename)
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(file_path, 'wb') as f:
                f.write(response.content)
            logging.info(f"Downloaded: {filename}")
        except Exception as e:
            logging.error(f"Failed to download {filename}: {e}")