"""Python wrapper for criminalip.io"""
import requests
import json
import dataclasses

URL_BASE = "https://api.criminalip.io/v1"
USER_AGENT = "CriminalIP Python Client 0.1"

def convert_bool(val: bool) -> str:
    return str(val).lower()

def build_full_url(url:str) -> str:
    return URL_BASE + url

@dataclasses.dataclass
class CriminalIP:
    api_key: str

    def _build_headers(self):
        headers = {"x-api-key":self.api_key,
                   "user-agent":USER_AGENT,
                   }
        return headers

    def _api_get(self, url: str):

        body = requests.get(build_full_url(url), headers=self._build_headers(), )
        data = body.text
        return json.loads(data)

    def _api_post(self, url: str, payload):
        body = requests.post(build_full_url(url), headers=self._build_headers(), data=payload)
        data = body.text
        return json.loads(data)

    def ip_data(self, ip: str, full: bool = False):
        url = f"/ip/data?ip={ip}&full={convert_bool(full)}"
        return self._api_get(url)

    def ip_summary(self, ip: str):
        url = f"/ip/summary?ip={ip}"
        return self._api_get(url)

    def ip_vpn(self, ip: str):
        url = f"/ip/vpn?ip={ip}"
        return self._api_get(url)

    def ip_hosting(self, ip: str, full: bool = False):
        url = f"/ip/hosting?ip={ip}&full={convert_bool(full)}"
        return self._api_get(url)

    def ip_malicious_info(self, ip: str):
        url = f"/feature/ip/malicious-info?ip={ip}"
        return self._api_get(url)

    def ip_privacy_threat(self, ip: str):
        url = f"/feature/ip/privacy-threat?ip={ip}"
        return self._api_get(url)

    def is_safe_dns_server(self, ip: str):
        url = f"/feature/ip/is_safe_dns_server?ip={ip}"
        return self._api_get(url)

    def ip_suspicious_info(self, ip: str):
        url = f"/feature/ip/suspicious-info?ip={ip}"
        return self._api_get(url)

    def exploit_search(self, exploit: str, offset: int = 0):
        url = f"/exploit/search?query={exploit}&offset={offset}"
        return self._api_get(url)

    def banner_search(self, service: str, offset: int = 0):
        url = "/banner/search?query={service}&offset={offset}"
        return self._api_get(url)

    def banner_stats(self, service: str):
        url = f"/banner/stats?query={service}"
        return self._api_get(url)

    def domain_reports(self, domain: str, offset: int):
        url = f"/domain/reports?query={domain}&offset={offset}"
        return self._api_get(url)

    def domain_reports_personal(self, offset: int = 0, public: bool = True, private: bool = False):
        url = f"/domain/reports/personal?offset={offset}&show_public={covert_bool(public)}&show_private={convert_bool(private)}"
        return self._api_get(url)

    def domain_report_id(self, id:int):
        url = f"/domain/report/{id}"
        return self._api_get(url)

    def domain_status(self, id:int):
        url = f"/domain/status/{id}"
        return self._api_get(url)

    def domain_scan(self, domain:str):
        url = f"/domain/scan"
        payload = {"query":domain}
        return self._api_post(url, payload)

    def domain_scan_private(self, domain:str):
        url = f"/domain/scan/private"
        payload = {"query":domain}
        return self._api_post(url, payload)

    def user_me(self):
        url = f"/user/me"
        payload = {}
        return self._api_post(url, payload)
