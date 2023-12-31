"""Python wrapper for criminalip.io"""
import requests
import json
import dataclasses
from http import HTTPStatus
from typing import Dict

from .constants import USER_AGENT
from .util import (
    _build_full_url,
    _convert_bool,
    CriminalIPServerException,
    CriminalIPAPIException,
)

import logging


@dataclasses.dataclass
class Client:
    api_key: str

    def _build_headers(self) -> Dict[str, str]:
        """Builds headers used for CriminalIP.

        Returns: Dictionary containing required header values.
        """

        headers = {
            "x-api-key": self.api_key,
            "user-agent": USER_AGENT,
        }
        return headers

    def _api_get(self, url: str):
        """Sends HTTP GET request to CriminalIP API.

        Args:
            url: The URL to GET.

        Returns:
            Dictionary containing data returned from the API.

        Raises:
            CriminalIPServerException: if api call results in server error.
            CriminalIPAPIException: If api call results in an error.
        """

        body = requests.get(
            _build_full_url(url),
            headers=self._build_headers(),
        )
        if body.status_code != HTTPStatus.OK:
            raise CriminalIPServerException(f"Status Code: {body.status_code}")

        data = json.loads(body.text)
        logging.info(f"got back data: {data}")

        if data["status"] != HTTPStatus.OK:
            raise CriminalIPAPIException(f"Error {data['status']}")
        return data

    def _api_post(self, url: str, payload):
        """Sends HTTP POST request to CriminalIP API.

        Args:
            url: The URL to POST to.
            payload: The data to send in the POST request.

        Returns:
            Dictionary containing data returned from the API.

        Raises:
            CriminalIPServerException: if api call results in server error.
            CriminalIPAPIException: If api call results in an error.
        """

        body = requests.post(
            _build_full_url(url), headers=self._build_headers(), data=payload
        )
        if body.status_code != HTTPStatus.OK:
            raise CriminalIPServerException(f"Status Code: {body.status_code}")

        data = json.loads(body.text)

        if data["status"] != HTTPStatus.OK:
            raise CriminalIPAPIException(f"Error {data['status']}")
        return data

    def ip_data(self, ip: str, full: bool = False):
        """Collects all data for the given IP address.

        Full API details https://www.criminalip.io/en/developer/api/get-ip-data

        Args:
            ip: The IP address to collect data for.
            full: Return full data if value is "full:true", return up to 20
                  lines if value is False.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """

        url = f"/ip/data?ip={ip}&full={_convert_bool(full)}"
        return self._api_get(url)

    def ip_summary(self, ip: str):
        """Collects  summarized information such as location data, ISP, owner,
        ASN, and other details for a specific IP address.

        Full API details
            https://www.criminalip.io/en/developer/api/get-ip-summary

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/ip/summary?ip={ip}"
        return self._api_get(url)

    def ip_vpn(self, ip: str):
        """Checks if given IP is in use as a VPN.

        Full API details https://www.criminalip.io/en/developer/api/get-ip-vpn

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/ip/vpn?ip={ip}"
        return self._api_get(url)

    def ip_hosting(self, ip: str, full: bool = False):
        """Checks if given IP is in use as a hosting provider.

        Full API details https://www.criminalip.io/en/developer/api/get-ip-hosting

        Args:
            ip: The IP address to collect data for.
            full: Return full data if value is "full:true", return up to 20 data
                  if value is False.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/ip/hosting?ip={ip}&full={_convert_bool(full)}"
        return self._api_get(url)

    def ip_malicious_info(self, ip: str):
        """Checks if IP is a known malicious IP address

        Full API details https://www.criminalip.io/en/developer/api/get-ip-malicious-info

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/feature/ip/malicious-info?ip={ip}"
        return self._api_get(url)

    def ip_privacy_threat(self, ip: str):
        """Checks if IP is a known privacy threat

        Full API details https://www.criminalip.io/en/developer/api/get-ip-privacy-threat

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/feature/ip/privacy-threat?ip={ip}"
        return self._api_get(url)

    def is_safe_dns_server(self, ip: str):
        """Checks whether the DNS service of a specific IP address is secure.

        Full API details https://www.criminalip.io/en/developer/api/get-ip-is-safe-dns-server

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/feature/ip/is_safe_dns_server?ip={ip}"
        return self._api_get(url)

    def ip_suspicious_info(self, ip: str):
        """Collects data suspected to be malicious, which is associated with a
           specific IP address.

        Full API details https://www.criminalip.io/en/developer/api/get-ip-suspicious-info

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/feature/ip/suspicious-info?ip={ip}"
        return self._api_get(url)

    def exploit_search(self, exploit: str, offset: int = 0):
        """Collects information on a specific CVE vulnerability.

        Full API details https://www.criminalip.io/en/developer/api/get-exploit-search

        Args:
            ip: The IP address to collect data for.

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/exploit/search?query={exploit}&offset={offset}"
        return self._api_get(url)

    def banner_search(self, service: str, offset: int = 0):
        """Collects search results of banners using filters

        Full API details https://www.criminalip.io/en/developer/api/get-banner-search

        Args:
            query: Original searching text containing filters
            offset: Starting position in the dataset (entering in increments of
                    10)

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = "/banner/search?query={service}&offset={offset}"
        return self._api_get(url)

    def banner_stats(self, service: str):
        """Collects statistics of banner search results.

        Full API details https://www.criminalip.io/en/developer/api/get-banner-stats

        Args:
            query: Original searching text containing filters

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/banner/stats?query={service}"
        return self._api_get(url)

    def domain_reports(self, domain: str, offset: int):
        """Collects scanned data on security information such as phishing,
           vulnerabilities, and more for a specific domain.

        Full API details https://www.criminalip.io/en/developer/api/get-domain-reports

        Args:
            query: Original searching text containing filters
            offset: Starting position in the dataset (entering in increments of
                    10)

        Returns:
            Dictionary containing data related to the IP.

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/domain/reports?query={domain}&offset={offset}"
        return self._api_get(url)

    def domain_reports_personal(
        self,
        offset: int = 0,
        public: bool = True,
        private: bool = False,
        scan_type: str = "full",
    ):
        """Collects a user's domain scan history.

        Full API details https://www.criminalip.io/developer/api/get-domain-reports-personal

        Args:
            offset: domain search page
            public: Retrieves a list of reports that were newly scanned in this
                    acccount, specifically those that were scanned with the
                    'public' option.
            private: Retrieves a list of reports that were newly scanned in this
                     acccount, specifically those that were scanned with the
                     'private' option.
            scan_type: This feature specifies the type of scan to look up.
                       (full: Full Scan, lite: Lite Scan.) The system will
                       automatically use Full Scan if no type is specified.

        Returns:
            Dictionary containing data containing user's domain reports

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = (
            f"/domain/reports/personal?offset={offset}&show_public="
            f"{_convert_bool(public)}&show_private={_convert_bool(private)}"
            f"&scan_type={scan_type}"
        )
        return self._api_get(url)

    def domain_report_id(self, id: int):
        """Collects domain information for a specific scan_id.

        Full API details https://www.criminalip.io/developer/api/get-domain-report-id

        Args:
            id: Retrieves a scan id of inputted domain if it were scanned previously

        Returns:
            Dictionary containing domain report info

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/domain/report/{id}"
        return self._api_get(url)

    def domain_status(self, id: int):
        """Checks whether there is a scan history for a specific domain.

        Full API details https://www.criminalip.io/developer/api/get-domain-status-id

        Args:
            id: Retrieves a scan id of inputted domain if it were scanned previously

        Returns:
            Dictionary containing scan percentage of

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = f"/domain/status/{id}"
        return self._api_get(url)

    def domain_scan(self, query: str):
        """Determines the scan_id for initiating a new scan of a specific domain.

        Full API details https://www.criminalip.io/developer/api/post-domain-scan

        Args:
            query: Domain Search Query

        Returns:
            Dictionary with query id

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = "/domain/scan"
        payload = {"query": query}
        return self._api_post(url, payload)

    def domain_scan_private(self, query: str):
        """Retrives security information such as phishing, vulnerabilities, and
           more for a specific domain in a confidential manner.

        Full API details https://www.criminalip.io/developer/api/post-domain-scan-private

        Args:
            query: Domain Search Query

        Returns:
            Dictionary with query id

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = "/domain/scan/private"
        payload = {"query": query}
        return self._api_post(url, payload)

    def user_me(self):
        """Retrives user information related to Criminal IP.

        Full API details https://www.criminalip.io/developer/api/post-user-me

        Returns:
            Dictionary with all user information

        Raises:
            CriminalIPException: when errors are generated from the API.
        """
        url = "/user/me"
        payload = {}
        return self._api_post(url, payload)

    def domain_lite_progress(self, scan_id: str):
        """Retrieves progress of a lite domain scan.

        Full API details https://www.criminalip.io/developer/api/get-domain-lite-progress

        Args:
            scan_id: Values used to distinguish domain reports.

        Returns:
            Dictionary containing scan progress.
        """
        url = f"/domain/lite/progress?scan_id={scan_id}"
        return self._api_get(url)

    def domain_lite_report(self, id: str):
        """Retrieves  Domain Search Lite Scan results.

        Full API detail https://www.criminalip.io/developer/api/get-domain-lite-report-id

        Args:
            scan_id: Values used to distinguish domain reports.

        Returns:
            Dictionary containing scan results.
        """
        url = f"/domain/lite/report/{id}"
        return self._api_get(url)

    def domain_lite_scan(self, query: str):
        """Initiates a Lite Scan for a new URL in Domain Search.

        Full API detail https://www.criminalip.io/developer/api/get-domain-lite-scan

        Args:
            query: The domain to query

        Returns:
            Dictionary containing scan id.
        """
        url = f"/domain/lite/scan?query={query}"
        return self._api_get(url)

    def domain_quick_hash_view(self, domain: str):
        """Checks if a specific URL is connected to a legitimate website or a
           malicious website.

        Full API detail https://www.criminalip.io/developer/api/get-domain-quick-hash-view

        Args:
            domain: URL to classify as a malicious or legitimate website.

        Returns:
            Dictionary containing domain info.
        """
        url = f"/domain/quick/hash/view?domain={domain}"
        return self._api_get(url)

    def domain_quick_malicious_view(self, domain: str):
        """Checks if a specific URL is connected to a malicious website.

        Full API detail https://www.criminalip.io/developer/api/get-domain-quick-malicious-view

        Args:
            domain: URL to verify for malicious website status

        Returns:
            Dictionary containing domain info.
        """
        url = f"/domain/quick/malicious/view?domain={domain}"
        return self._api_get(url)

    def domain_quick_trusted_view(self, domain: str):
        """Checks if a specific URL is connected to a legitimate website.

        Full API details https://www.criminalip.io/developer/api/get-domain-quick-trusted-view

        Args:
            domain: URL to verify for legitimate website status

        Returns:
            Dictionary containing domain info.
        """
        url = f"/domain/quick/trusted/view?domain={domain}"
        return self._api_get(url)
