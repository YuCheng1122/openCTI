from datetime import datetime, timedelta
import requests
import urllib3
import json
import re
import os
import logging
from typing import Optional, List, Dict, Any
from config import Config

class OpenCTICollector:
    def __init__(self, config: Config):
        self.logger = logging.getLogger(__name__)
        try:
            self.config = config
            if not config.opencti.verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            self.headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {config.opencti.password}' 
            }
            self.api_url = config.opencti.api_url
            self.logger.info(f"OpenCTI collector initialized with API URL: {self.api_url}")
        except Exception as e:
            self.logger.error(f"Failed to initialize OpenCTI collector: {str(e)}")
            raise

    def query(self, query: str) -> Optional[Dict]:
        """
        執行 GraphQL 查詢
        
        Args:
            query: GraphQL 查詢字串
            
        Returns:
            Optional[Dict]: 如果成功返回響應數據，否則返回 None
        """
        try:
            self.logger.debug(f"Sending GraphQL query to {self.api_url}")
            response = requests.post(
                self.api_url,
                headers=self.headers,  # 只使用 headers，移除 auth
                json={'query': query},
                verify=self.config.opencti.verify_ssl
            )
            
            # 檢查 HTTP 狀態碼
            if response.status_code == 401:
                self.logger.error("Authentication failed. Please check your API key.")
                return None
            
            response.raise_for_status()
            
            # 解析響應
            data = response.json()
            
            # 檢查 GraphQL 錯誤
            if 'errors' in data:
                self.logger.error(f"GraphQL errors: {data['errors']}")
                return None
                
            return data
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response status code: {e.response.status_code}")
                self.logger.error(f"Response content: {e.response.text}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse API response: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in query: {str(e)}")
            return None

    def _build_indicator_query(self, start_time: str, end_time: str, limit: int) -> str:
        """
        構建指標查詢
        
        Args:
            start_time: 起始時間
            end_time: 結束時間
            limit: 結果數量限制
            
        Returns:
            str: GraphQL 查詢字串
        """
        return f'''{{
          indicators(
            orderBy: created_at,
            orderMode: desc,
            first: {limit},
            filters: {{
              filters: [
                {{ key: "created_at", operator: gte, values: ["{start_time}"] }},
                {{ key: "created_at", operator: lt, values: ["{end_time}"] }}
              ],
              filterGroups: [],
              mode: and
            }}
          ) {{
            edges {{
              node {{
                id
                name
                pattern
                description
                created_at
                createdBy {{
                  name
                }}
              }}
            }}
          }}
        }}'''

    def get_indicators(self) -> Optional[Dict]:
        """
        獲取今天和昨天的指標數據
        
        Returns:
            Optional[Dict]: 包含指標數據的字典，如果失敗返回 None
        """
        try:
            today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            tomorrow = today + timedelta(days=1)
            yesterday = today - timedelta(days=1)

            self.logger.info(f"Fetching indicators for period: {yesterday.isoformat()} to {tomorrow.isoformat()}")

            # 查詢今天的指標
            query = self._build_indicator_query(
                start_time=today.isoformat(),
                end_time=tomorrow.isoformat(),
                limit=self.config.opencti.limit
            )
            
            today_indicators = self.query(query)
            if not today_indicators:
                self.logger.error("Failed to fetch today's indicators")
                return None

            if 'data' not in today_indicators:
                self.logger.error(f"Unexpected API response format: {today_indicators}")
                return None

            today_count = len(today_indicators['data']['indicators']['edges'])
            self.logger.info(f"Retrieved {today_count} indicators for today")

            # 如果今天的數據不足，查詢昨天的數據
            if today_count < self.config.opencti.limit:
                remaining_limit = self.config.opencti.limit - today_count
                yesterday_query = self._build_indicator_query(
                    start_time=yesterday.isoformat(),
                    end_time=today.isoformat(),
                    limit=remaining_limit
                )
                
                yesterday_indicators = self.query(yesterday_query)
                if yesterday_indicators and 'data' in yesterday_indicators:
                    yesterday_count = len(yesterday_indicators['data']['indicators']['edges'])
                    self.logger.info(f"Retrieved {yesterday_count} indicators for yesterday")
                    today_indicators['data']['indicators']['edges'].extend(
                        yesterday_indicators['data']['indicators']['edges']
                    )

            return today_indicators
        except Exception as e:
            self.logger.error(f"Error in get_indicators: {str(e)}")
            raise
    
    def save_indicators(self) -> None:
        """保存指標數據到文件"""
        try:
            self.logger.info("Starting to save indicators")
            indicators = self.get_indicators()
            
            if not indicators:
                raise ValueError("No indicators data received from API")

            if 'data' not in indicators:
                raise ValueError(f"Unexpected response format: {indicators}")

            if 'indicators' not in indicators['data']:
                raise ValueError(f"No indicators in response: {indicators['data']}")

            if 'edges' not in indicators['data']['indicators']:
                raise ValueError(f"No edges in indicators: {indicators['data']['indicators']}")

            formatted_indicators = []
            for edge in indicators['data']['indicators']['edges']:
                try:
                    node = edge['node']
                    formatted_indicators.append({
                        "id": node['id'],
                        "type": self._determine_type(node['pattern']),
                        "name": node['name'],
                        "pattern": node['pattern'],
                        "description": node['description'],
                        "created_at": node['created_at'],
                        "author": node.get('createdBy', {}).get('name', 'Unknown')
                    })
                except KeyError as e:
                    self.logger.error(f"Missing required field in node: {e}")
                    continue

            # 確保輸出目錄存在
            os.makedirs(self.config.path.base_dir, exist_ok=True)
            
            # 生成輸出文件路徑
            filename = os.path.join(
                self.config.path.base_dir,
                f"{datetime.utcnow().strftime('%Y-%m-%d-%H-%M')}_Ioc.json"
            )

            # 保存數據
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(formatted_indicators, f, indent=4, ensure_ascii=False)
            
            self.logger.info(f"Successfully saved {len(formatted_indicators)} indicators to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save indicators: {str(e)}")
            self.logger.exception("Detailed error trace:")
            raise

    @staticmethod
    def _determine_type(pattern: str) -> str:
        """
        根據模式確定指標類型
        
        Args:
            pattern: 指標模式字串
            
        Returns:
            str: 指標類型
        """
        patterns = {
            'ipv4': r"\[ipv4-addr:value = '([0-9]{1,3}\.){3}[0-9]{1,3}'\]",
            'ipv6': r"\[ipv6-addr:value = '([0-9a-fA-F:]+)'\]",
            'domain': r"\[domain-name:value = '[^\s'\"]+'\]",
            'url': r"\[url:value = 'https?://[^\s'\"]+'\]",
            'email': r"\[email-addr:value = '[^\s'\"]+@[^\s'\"]+'\]"
        }
        
        for type_name, regex in patterns.items():
            if re.search(regex, pattern):
                return type_name
        return 'unknown'