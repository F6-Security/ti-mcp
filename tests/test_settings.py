# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Environment settings are validated when the server starts, before any key leaves the process."""

import os
import tempfile
import unittest
import unittest.mock

from support import settings
from ti_mcp.client import TIClient
from ti_mcp.settings import Settings, SettingsError


class TestBaseUrl(unittest.TestCase):
    def test_default_is_the_production_host(self):
        self.assertEqual(settings().base_url, "https://ti.f6.security")

    def test_trailing_slash_and_api_root_are_stripped(self):
        loaded = settings(TI_BASE_URL="https://stage.example.com/api/v2/")
        self.assertEqual(loaded.base_url, "https://stage.example.com")

    def test_http_is_refused(self):
        with self.assertRaisesRegex(SettingsError, "https://"):
            settings(TI_BASE_URL="http://ti.example.com")

    def test_query_and_fragment_are_refused(self):
        for url in ("https://ti.example.com/?x=1", "https://ti.example.com/#frag"):
            with self.subTest(url=url), self.assertRaisesRegex(SettingsError, "query string or fragment"):
                settings(TI_BASE_URL=url)

    def test_embedded_credentials_are_refused(self):
        with self.assertRaisesRegex(SettingsError, "credentials"):
            settings(TI_BASE_URL="https://user:key@ti.example.com")

    def test_missing_host_is_refused(self):
        with self.assertRaisesRegex(SettingsError, "host"):
            settings(TI_BASE_URL="https://")


class TestCaBundle(unittest.TestCase):
    def test_default_verifies_with_system_store(self):
        self.assertIs(settings().verify, True)

    def test_missing_file_is_refused(self):
        with self.assertRaisesRegex(SettingsError, "not a file"):
            settings(TI_CA_BUNDLE="/nonexistent/ca.pem")

    def test_garbage_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as bundle:
            bundle.write("not a certificate")
        try:
            with self.assertRaisesRegex(SettingsError, "could not be loaded"):
                settings(TI_CA_BUNDLE=bundle.name)
        finally:
            os.unlink(bundle.name)


class TestProxy(unittest.TestCase):
    def test_environment_proxies_are_ignored(self):
        loaded = settings(HTTPS_PROXY="http://ambient:3128", HTTP_PROXY="http://ambient:3128")
        self.assertIsNone(loaded.proxy)
        self.assertTrue(loaded.ambient_proxy)
        client = TIClient(loaded)._http
        self.assertFalse(client.trust_env)
        self.assertEqual(client._mounts, {})

    def test_explicit_proxy_is_used(self):
        loaded = settings(TI_PROXY="http://proxy.example.com:3128")
        self.assertEqual(loaded.proxy, "http://proxy.example.com:3128")
        client = TIClient(loaded)._http
        self.assertEqual(len(client._mounts), 1)

    def test_other_schemes_are_refused(self):
        with self.assertRaisesRegex(SettingsError, "http:// or https://"):
            settings(TI_PROXY="socks5://proxy.example.com:1080")


class TestNumbers(unittest.TestCase):
    def test_defaults(self):
        loaded = settings()
        self.assertEqual(
            (loaded.timeout, loaded.retries, loaded.min_feed_interval, loaded.result_id_ttl), (120, 3, 1, 150)
        )

    def test_unparsable_value_names_the_variable(self):
        with self.assertRaisesRegex(SettingsError, "TI_TIMEOUT must be a number"):
            settings(TI_TIMEOUT="soon")
        with self.assertRaisesRegex(SettingsError, "TI_RETRIES must be an integer"):
            settings(TI_RETRIES="1.5")

    def test_below_minimum_is_refused(self):
        with self.assertRaisesRegex(SettingsError, "TI_TIMEOUT must be at least 1"):
            settings(TI_TIMEOUT="0")

    def test_credentials_are_stripped(self):
        loaded = settings(TI_LOGIN="  user@example.com ", TI_API_KEY=" key\n")
        self.assertEqual((loaded.login, loaded.api_key), ("user@example.com", "key"))

    def test_missing_credentials_do_not_stop_the_server(self):
        # Every tool call then says what to set; see test_client.
        loaded = settings(TI_LOGIN="", TI_API_KEY="")
        self.assertEqual((loaded.login, loaded.api_key), ("", ""))


class TestSecretsStayOutOfRepr(unittest.TestCase):
    def test_key_and_proxy_password_are_not_in_repr(self):
        loaded = settings(TI_API_KEY="s3cret-key", TI_PROXY="http://puser:psecret@proxy.local:3128")
        text = repr(loaded)
        self.assertNotIn("s3cret-key", text)
        self.assertNotIn("psecret", text)
        self.assertEqual(loaded.proxy_display, "proxy.local:3128")


class TestEnvironmentIsReadOnce(unittest.TestCase):
    def test_from_env_reads_os_environ_by_default(self):
        env = {"TI_LOGIN": "a", "TI_API_KEY": "b", "TI_TIMEOUT": "7"}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            loaded = Settings.from_env()
        self.assertEqual((loaded.login, loaded.timeout), ("a", 7))


if __name__ == "__main__":
    unittest.main()
