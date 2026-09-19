import unittest
from diagnostico.validacoes import validar_alvo_rede, validar_url_http, validar_porta_tcp

class TestValidacoes(unittest.TestCase):
    def test_validar_alvo_rede_validos(self):
        self.assertEqual(validar_alvo_rede("8.8.8.8"), "8.8.8.8")
        self.assertEqual(validar_alvo_rede("google.com"), "google.com")
        self.assertEqual(validar_alvo_rede("2001:4860:4860::8888"), "2001:4860:4860::8888")
        self.assertEqual(validar_alvo_rede("my-host-123.local"), "my-host-123.local")

    def test_validar_alvo_rede_invalidos(self):
        invalid_targets = [
            "8.8.8.8;id",
            "google.com && whoami",
            "$(id)",
            "`id`",
            "8.8.8.8\nid",
            "-help",
            "--version",
            "",
            "   ",
            "this is a test",
            "http://google.com"  # Not a valid raw hostname
        ]
        for target in invalid_targets:
            with self.assertRaises(ValueError):
                validar_alvo_rede(target)

    def test_validar_url_http_validas(self):
        self.assertEqual(validar_url_http("http://google.com"), "http://google.com")
        self.assertEqual(validar_url_http("https://192.168.1.1:8443/test?q=1"), "https://192.168.1.1:8443/test?q=1")

    def test_validar_url_http_invalidas(self):
        invalid_urls = [
            "ftp://server.com",
            "file:///etc/passwd",
            "gopher://old.com",
            "data:text/html,test",
            "javascript:alert(1)",
            "http://-invalid.com",
            "https://google.com;id",
            "https://google.com\nid"
        ]
        for url in invalid_urls:
            with self.assertRaises(ValueError):
                validar_url_http(url)

    def test_validar_porta_tcp(self):
        self.assertEqual(validar_porta_tcp(80), 80)
        self.assertEqual(validar_porta_tcp("443"), 443)

        with self.assertRaises(ValueError):
            validar_porta_tcp(0)
        with self.assertRaises(ValueError):
            validar_porta_tcp(65536)
        with self.assertRaises(ValueError):
            validar_porta_tcp("not a port")
