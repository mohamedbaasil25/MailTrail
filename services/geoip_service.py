# Triggered reload to load new MMDB database
import re
import math
import hashlib
import logging
from typing import Optional, List, Dict, Tuple
from datetime import datetime, timezone
import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

# A small, deliberately global/neutral spread of demo locations used only
# when a real GeoLite2 lookup isn't possible (no DB file installed, or the
# address simply isn't in MaxMind's data - e.g. RFC 5737 documentation
# ranges used in sample/test emails). This exists so the Geo Intelligence
# feature is demonstrable out of the box without requiring a MaxMind
# license key, per the constructor's own (previously unimplemented) log
# message promising "mock data for demonstration". Every result derived
# this way is tagged source="simulated" so callers/UI never confuse it
# with a real attribution - it must never be presented as real intel.
_SIMULATED_LOCATIONS = [
    {"city": "Singapore", "country": "SG", "lat": 1.3521, "lon": 103.8198},
    {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
    {"city": "Sao Paulo", "country": "BR", "lat": -23.5505, "lon": -46.6333},
    {"city": "Toronto", "country": "CA", "lat": 43.6532, "lon": -79.3832},
    {"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093},
    {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041},
    {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
    {"city": "Johannesburg", "country": "ZA", "lat": -26.2041, "lon": 28.0473},
]


def _simulated_geo(ip_address: str) -> Dict:
    """
    Deterministic pseudo-location for an IP: the same IP always maps to the
    same simulated city, so re-analyzing the same sender twice in a demo
    still behaves consistently (and so two different sender IPs plausibly
    land in two different places, which is what makes the impossible-travel
    check demonstrable at all without a real GeoIP database).
    """
    digest = hashlib.sha256(ip_address.encode()).hexdigest()
    location = _SIMULATED_LOCATIONS[int(digest, 16) % len(_SIMULATED_LOCATIONS)]
    return {
        "country": location["country"],
        "city": location["city"],
        "lat": location["lat"],
        "lon": location["lon"],
        "ip": ip_address,
        "source": "simulated",
    }


class GeoIPService:
    def __init__(self, db_path: str = "GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        try:
            # Requires downloading the MaxMind GeoLite2 City database
            self.reader = geoip2.database.Reader(self.db_path)
            logger.info(f"Loaded GeoIP database from {self.db_path}")
        except FileNotFoundError:
            logger.warning(f"GeoIP database not found at {self.db_path}. GeoIP lookups will fall back to simulated locations for demonstration.")
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
        Queries the MaxMind database for geolocation info. Falls back to a
        clearly-labeled simulated location (see _simulated_geo) whenever a
        real answer isn't available - either because no GeoLite2-City.mmdb
        is installed, or because the address isn't in MaxMind's dataset
        (e.g. the RFC 5737 documentation ranges used by this app's own
        sample emails). A missing/unresolvable lookup should never mean
        "the Geo Intelligence feature silently does nothing".
        """
        if not ip_address:
            return None

        if not self.reader:
            return _simulated_geo(ip_address)

        try:
            response = self.reader.city(ip_address)
            return {
                "country": response.country.iso_code,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "ip": ip_address,
                "source": "maxmind",
            }
        except geoip2.errors.AddressNotFoundError:
            logger.info(f"IP {ip_address} not found in GeoIP database; using simulated location.")
            return _simulated_geo(ip_address)
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return _simulated_geo(ip_address)

    def check_impossible_travel(self, current_geo: Dict, last_login: Dict) -> Tuple[bool, float, float]:
        """
        Calculates distance and speed between current location and last known location.
        Returns (is_impossible, speed_kmh, distance_km).
        """
        if not current_geo or not last_login:
            return False, 0.0, 0.0

        lat1, lon1 = last_login.get("lat"), last_login.get("lon")
        lat2, lon2 = current_geo.get("lat"), current_geo.get("lon")
        
        if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
            return False, 0.0, 0.0

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
        t2 = current_geo.get("timestamp", datetime.now(timezone.utc))
        
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
        return is_impossible, speed_kmh, distance_km

# Singleton instance
geoip_service = GeoIPService()
