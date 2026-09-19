import unittest
from diagnostico.parsers import parse_ping_output, parse_mtr_json, parse_ip_j

class TestParsers(unittest.TestCase):
    def test_parse_ping_output_linux(self):
        stdout = '''PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=14.9 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=116 time=15.1 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=116 time=14.8 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=116 time=15.0 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 14.810/14.955/15.120/0.145 ms
'''
        res = parse_ping_output(stdout)
        self.assertEqual(res["sent"], 4)
        self.assertEqual(res["received"], 4)
        self.assertEqual(res["loss_percent"], 0.0)
        self.assertEqual(res["min_ms"], 14.810)
        self.assertEqual(res["avg_ms"], 14.955)
        self.assertEqual(res["max_ms"], 15.120)
        self.assertEqual(res["mdev_ms"], 0.145)

    def test_parse_ping_output_loss(self):
        stdout = '''
--- 1.2.3.4 ping statistics ---
4 packets transmitted, 1 received, 75% packet loss, time 3065ms
rtt min/avg/max/mdev = 10.0/10.0/10.0/0.0 ms
'''
        res = parse_ping_output(stdout)
        self.assertEqual(res["loss_percent"], 75.0)
        self.assertEqual(res["received"], 1)

    def test_parse_mtr_json(self):
        stdout = '''{
            "report": {
                "mtr": {
                    "src": "moonshield",
                    "dst": "8.8.8.8",
                    "tos": 0
                },
                "hubs": [
                    {
                        "count": 1,
                        "host": "192.168.1.1",
                        "Loss%": 0.0,
                        "Snt": 10,
                        "Last": 1.5,
                        "Avg": 1.6,
                        "Best": 1.2,
                        "Wrst": 2.1,
                        "StDev": 0.3
                    }
                ]
            }
        }'''
        res = parse_mtr_json(stdout)
        self.assertEqual(len(res["hops"]), 1)
        self.assertEqual(res["hops"][0]["ip"], "192.168.1.1")
        self.assertEqual(res["hops"][0]["loss_percent"], 0.0)

    def test_parse_ip_j(self):
        stdout = '[{"ifindex": 1, "ifname": "lo"}]'
        res = parse_ip_j(stdout)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["ifname"], "lo")
