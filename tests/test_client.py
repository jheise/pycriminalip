"""Unit tests for CriminalIP client object."""
import unittest
import json
from http import HTTPStatus
from unittest.mock import MagicMock, patch
from unittest import mock
import requests

from criminalip import client
from criminalip import util


class TestClient(unittest.TestCase):
    # @patch('requests.get')
    @mock.patch.object(requests, "get")
    def test_client_api_get(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.text = json.dumps({"status": 200, "ip": "10.0.0.1"})

        mock_requests.return_value = mock_response

        crimip = client.Client("apikeyvalue")

        try:
            data = crimip._api_get("http://criminalip.test.url")
        except Exception:
            self.fail("._api_get failed")

        self.assertEqual(data["ip"], "10.0.0.1")

    @mock.patch.object(requests, "get")
    def test_client_api_get_raise_server_exception(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = HTTPStatus.FORBIDDEN

        mock_requests.return_value = mock_response

        crimip = client.Client("apikeyvalue")

        with self.assertRaises(util.CriminalIPServerException):
            crimip._api_get("http://criminalip.test.url")

    @mock.patch.object(requests, "get")
    def test_client_api_get_raise_api_exception(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.text = json.dumps({"status": 500, "ip": "10.0.0.1"})

        mock_requests.return_value = mock_response

        crimip = client.Client("apikeyvalue")

        with self.assertRaises(util.CriminalIPAPIException):
            crimip._api_get("http://criminalip.test.url")

    @mock.patch.object(requests, "post")
    def test_client_api_post(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.text = json.dumps({"status": 200, "ip": "10.0.0.1"})

        mock_requests.return_value = mock_response

        crimip = client.Client("apikeyvalue")

        try:
            data = crimip._api_post("http://criminalip.test.url", {"ip": "10.0.0.1"})
        except Exception:
            self.fail("._api_post failed")

        self.assertEqual(data["ip"], "10.0.0.1")

    @mock.patch.object(requests, "post")
    def test_client_api_post_raises_server_exception(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = HTTPStatus.FORBIDDEN

        mock_requests.return_value = mock_response

        crimip = client.Client("apikeyvalue")

        with self.assertRaises(util.CriminalIPServerException):
            crimip._api_post("http://criminalip.test.url", {"ip": "10.0.0.1"})

    @mock.patch.object(requests, "post")
    def test_client_api_post_raises_api_exception(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = HTTPStatus.OK
        mock_response.text = json.dumps({"status": 500, "ip": "10.0.0.1"})

        mock_requests.return_value = mock_response

        crimip = client.Client("apikeyvalue")
        with self.assertRaises(util.CriminalIPAPIException):
            crimip._api_post("http://criminalip.test.url", {"ip": "10.0.0.1"})
