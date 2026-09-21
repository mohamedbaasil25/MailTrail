# Triggered reload to load new MMDB database
import re
import math
import logging
from typing import Optional, List, Dict, Tuple
from datetime import datetime
import geoip2.database

logger = logging.getLogger(__name__)

class GeoIPService:
    def __init__(self, db_path: str = "GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        try:
            # Requires downloading the MaxMind GeoLite2 City database
            self.reader = geoip2.database.Reader(self.db_path)
            logger.info(f"Loaded GeoIP database from {self.db_path}")
        except FileNotFoundError:
            logger.warning(f"GeoIP database not found at {self.db_path}. GeoIP lookups will return mock data for demonstration.")
        except Exception as e:
            logger.error(f"Error loading GeoIP database: {e}")

    def extract_sender_ip(self, headers: List) -> Optional[str]:
        """
        Parses 'Received' headers to find the originating public IP address.
        """
        if not headers:
            return None

        # Basic IPv4 extraction pattern
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # 'Received' headers are prepended by each MTA in reverse chronological order.
        # The last 'Received' header in the list is typically the first hop (closest to the sender).
        received_headers = [h.value for h in headers if h.name.lower() == 'received']
        
        for header_val in reversed(received_headers):
            ips = ip_pattern.findall(header_val)
            for ip in ips:
                # Basic check to skip private/local IPs
                if (ip.startswith("10.") or 
                    ip.startswith("192.168.") or 
                    ip.startswith("127.") or 
                    re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip)):
                    continue
                return ip
                
        return None

    def lookup_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Queries MaxMind database for geolocation info.
        """
        if not ip_address:
            return None
            
        if not self.reader:
            logger.warning(f"GeoIP database missing. Cannot lookup {ip_address}.")
            return None

        try:
            response = self.reader.city(ip_address)
            return {
                "country": response.country.iso_code,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "ip": ip_address
            }
        except geoip2.errors.AddressNotFoundError:
            logger.info(f"IP {ip_address} not found in GeoIP database.")
            return None
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return None

    def check_impossible_travel(self, current_geo: Dict, last_login: Dict) -> Tuple[bool, float]:
        """
        Calculates distance and speed between current location and last known location.
        Returns (is_impossible, speed_kmh).
        """
        if not current_geo or not last_login:
            return False, 0.0

        lat1, lon1 = last_login.get("lat"), last_login.get("lon")
        lat2, lon2 = current_geo.get("lat"), current_geo.get("lon")
        
        if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
            return False, 0.0

        # Calculate distance using Haversine formula
        R = 6371.0 # Earth radius in km
        dLat = math.radians(lat2 - lat1)
        dLon = math.radians(lon2 - lon1)
        a = (math.sin(dLat / 2)**2 + 
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dLon / 2)**2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance_km = R * c

        # Calculate time difference in hours
        t1 = last_login.get("timestamp")
        t2 = current_geo.get("timestamp", datetime.utcnow())
        
        if isinstance(t1, str):
            t1 = datetime.fromisoformat(t1.replace('Z', '+00:00'))
        if isinstance(t2, str):
            t2 = datetime.fromisoformat(t2.replace('Z', '+00:00'))
            
        time_diff_hours = abs((t2 - t1).total_seconds()) / 3600.0

        if time_diff_hours <= 0:
            speed_kmh = float('inf') if distance_km > 0 else 0.0
        else:
            speed_kmh = distance_km / time_diff_hours

        # Commercial flights average ~900 km/h. If speed > 1000 km/h, it's highly suspicious.
        is_impossible = speed_kmh > 1000.0
        return is_impossible, speed_kmh

# Singleton instance
geoip_service = GeoIPService()
