"""
MIT License

Copyright (c) 2020 Insane Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from pyshark import FileCapture, LiveCapture
from argparse import ArgumentParser
from json import dumps, loads
from base64 import b64decode
from traceback import print_exc
from elasticsearch import Elasticsearch, helpers
from time import time
from datetime import datetime
import binascii


test_data = [
        {
                "@timestamp": "2016-09-29T08:33:28",
                "network.transport": "TCP",
                "source.mac": "00:50:56:c0:00:08",
                "destination.mac": "00:0c:29:8a:3d:a7",
                "source.address": "192.168.43.1",
                "source.ip": "192.168.43.1",
                "destination.address": "192.168.43.135",
                "destination.ip": "192.168.43.135",
                "source.port": "50999",
                "destination.port": "12345",
                "websocket.masked": 1,
                "websocket.key": "b7:ce:fd:57",
                "websocket.masked_payload": "Masked payload",
                "websocket.payload": dumps(
                    {
                        "children":
                            [
                                {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                                {"name": "action", "value": "YXV0aC5wYXNzZWQ="},
                                {"name": "token", "value": "AIzX7mWtXtkJOBPeiVtC/0Nyofzgs+GZjZbwi0dd8Ak6/RtktfYjUltekzJXNt+CrGvG+ClA\r\n7Hmq772qrvUUjI/8g9MlDRN8vy+ZBcclCSv6KtBZ1+nxV285tquowBIEsEiYGX+ULzdhaG3I\r\nvHO/R8Me5xQqkRoS51LadZUY8SzEZ/0Eyg5Dtcu9ESzA3mldahqt0gVNExpcr7RfcrlDcfC2\r\nkdEzvckIlSDaHbcVT3y9GAp6IUgpmZuSFBkgXHfslUFmNvoAl/Tl5qFzi40woEU2f9kC6JWJ\r\n3zCBj+dvCL/oyaoXu7qBOf5hm32/ZjYP+N9AXJI0Jj8zLVb/rjiKoA=="}
                            ]
                    }
                ),
                "network.protocol": [
                    "eth",
                    "ip",
                    "tcp",
                    "websocket",
                    "data-text-lines"
                ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                            {"name": "action", "value": "YXV0aC5oZWxsbw=="},
                            {"name": "mode", "value": "bG9naW4="},
                            {"name": "serverid",
                             "value": "6EJKTebFfyODBcBqM+JBVCwJkoM="},
                            {"name": "token", "value": "+ynYaT4H/8N+EbEx59kDlg=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                            {"name": "action", "value": "YXV0aC5sb2dpbg=="},
                            {"name": "mode", "value": "c2lnbmlu"},
                            {"name": "clientid",
                             "value": "FUegGfcIMH53hGX31fZuQg=="},
                            {"name": "token", "value": "WAKDUg4GCbPZTyea12NqnQ=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                            {"name": "action", "value": "YXV0aC5sb2dpbg=="},
                            {"name": "mode", "value": "c2lnbmlu"},
                            {"name": "clientid",
                             "value": "FUegGfcIMH53hGX31fZuQg=="},
                            {"name": "token", "value": "WAKDUg4GCbPZTyea12NqnQ=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                            {"name": "action", "value": "YXV0aC5wZW5kaW5n"},
                            {"name": "clientid",
                             "value": "D7MSQ8AJxrZxxd3GCNYK+cs7rp1EbcsdI1Sb3SlZjSy5Ayyi1BI7Xw32KCqjs0pe"},
                            {"name": "clientkey", "value": "PMC3eUxbK9TkZ6ofyV8HyUNj5jVNAGHUA9Qbu3RUYmI="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                            {"name": "action", "value": "YXV0aC5jb21taXQ="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "Y2xvdWQuYXV0aA=="},
                            {"name": "action", "value": "YXV0aC5wYXNzZWQ="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "action", "value": "dHJhbnNmZXJfcmVxdWVzdA=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "src_id", "value": "ZTM5MTg0N2MtYmFlNy0xMWVhLWI0YmMtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"},
                            {"name": "local_path", "value": "L3RtcC9wYXNzd2Q="},
                            {"name": "remote_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"},
                            {"name": "remote_path", "value": "L2V0Yy9wYXNzd2Q="},
                            {"name": "mode", "value": "ZG93bmxvYWQ="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "path", "value": "L3RtcC9zdGFnZXovcGFzc3dk"},
                            {"name": "mode", "value": "cg=="},
                            {"name": "action", "value": "b3Blbg=="},
                            {"name": "src_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "size", "value": "MTk0OQ=="},
                            {"name": "action", "value": "b3Blbl9zdWNjZXNz"},
                            {"name": "src_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "action", "value": "cmVhZA=="},
                            {"name": "src_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "src_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"},
                            {"name": "action", "value": "cmVhZF9kYXRh"},
                            {"name": "offset", "value": "MA=="},
                            {"name": "data", "value": ""}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "action", "value": "Y2xvc2U="},
                            {"name": "src_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "ZmlsZQ=="},
                            {"name": "session_id", "value": "UGRrQnh2MnQzVzBsa0U4Zg=="},
                            {"name": "src_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "YjkyMzdlYzAtYmFlNy0xMWVhLTlkYTAtMDAwYzI5MTMwYjcx"},
                            {"name": "action", "value": "cmVhZF9kYXRh"},
                            {"name": "offset", "value": "MA=="},
                            {"name": "data", "value": ""}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "bW9uaXRvcg=="},
                            {"name": "action", "value": "ZmlsZV9hZGRfcmVxdWVzdA=="},
                            {"name": "client_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"},
                            {"name": "mon_id", "value": "Mzk1NjAyNTQtNjIyZS1iMDIyLTNlYmUtNDA0ODY3ZjlhYTRk"},
                            {"name": "mask", "value": "Y29sbGVjdHo="},
                            {"name": "active", "value": "dHJ1ZQ=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "bW9uaXRvcg=="},
                            {"name": "action", "value": "bmV0X2xpc3RfcmVxdWVzdA=="},
                            {"name": "client_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "bW9uaXRvcg=="},
                            {"name": "action", "value": "bmV0X2xpc3RfcmVwbHk="},
                            {"name": "client_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"},
                            {"name": "records", "value":
                                [
                                    [
                                        {"name": "mon_id", "value": "MmZjYTllY2MtOWM0Mi0xOWRhLTlmYWItOGZlMmU5ZmI3YmUx"},
                                        {"name": "port", "value": "MTIzNDU="},
                                        {"name": "proto", "value": "dGNw"},
                                        {"name": "active", "value": "dHJ1ZQ=="},
                                        {"name": "client_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"}
                                    ],
                                    [
                                        {"name": "mon_id", "value": "OTU0NTI0MDEtM2QxYy0zMWZmLTVmOTgtZTY0MjdmYTVlNWQ4"},
                                        {"name": "port", "value": "NDU2Nzg="},
                                        {"name": "proto", "value": "dGNw"},
                                        {"name": "active", "value": "dHJ1ZQ=="},
                                        {"name": "client_id", "value": "YzhiNDY0ODAtYmFlNy0xMWVhLWI2ZWYtMDAwYzI5MTMwYjcx"}
                                    ]
                                ]
                             }
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
{
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "c2hlbGw="},
                            {"name": "action", "value": "b3Blbg=="},
                            {"name": "session.id", "value": "ODhjY2ExMjI0NjRiOGNiNGViMWE3NDYyYWM4NDA5Mjc5YjAxMTU5Mw=="},
                            {"name": "src_id", "value": "OTcyMDVjZGMtYzA2Yy0xMWVhLTk0MWEtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "OTYwNWRlMjYtYzA2Yy0xMWVhLWI2NTAtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
{
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "c2hlbGw="},
                            {"name": "action", "value": "b3Blbi5zdWNjZXNz"},
                            {"name": "session.id", "value": "ODhjY2ExMjI0NjRiOGNiNGViMWE3NDYyYWM4NDA5Mjc5YjAxMTU5Mw=="},
                            {"name": "src_id", "value": "OTYwNWRlMjYtYzA2Yy0xMWVhLWI2NTAtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "OTcyMDVjZGMtYzA2Yy0xMWVhLTk0MWEtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
{
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "c2hlbGw="},
                            {"name": "action", "value": "ZGF0YQ=="},
                            {"name": "session.id", "value": "ODhjY2ExMjI0NjRiOGNiNGViMWE3NDYyYWM4NDA5Mjc5YjAxMTU5Mw=="},
                            {"name": "src_id", "value": "OTcyMDVjZGMtYzA2Yy0xMWVhLTk0MWEtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "OTYwNWRlMjYtYzA2Yy0xMWVhLWI2NTAtMDAwYzI5MTMwYjcx"},
                            {"name": "data", "value": "aWQNCg=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
{
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "c2hlbGw="},
                            {"name": "action", "value": "ZGF0YQ=="},
                            {"name": "session.id", "value": "ODhjY2ExMjI0NjRiOGNiNGViMWE3NDYyYWM4NDA5Mjc5YjAxMTU5Mw=="},
                            {"name": "src_id", "value": "OTYwNWRlMjYtYzA2Yy0xMWVhLWI2NTAtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "OTcyMDVjZGMtYzA2Yy0xMWVhLTk0MWEtMDAwYzI5MTMwYjcx"},
                            {"name": "data", "value": "YmFzaC00LjEjIGlkCnVpZD0wKHJvb3QpIGdpZD0wKHJvb3QpIGdyb3Vwcz0wKHJvb3Qp"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "c2hlbGw="},
                            {"name": "action", "value": "Y2xvc2U="},
                            {"name": "session.id", "value": "ODhjY2ExMjI0NjRiOGNiNGViMWE3NDYyYWM4NDA5Mjc5YjAxMTU5Mw=="},
                            {"name": "src_id", "value": "OTcyMDVjZGMtYzA2Yy0xMWVhLTk0MWEtMDAwYzI5MTMwYjcx"},
                            {"name": "dst_id", "value": "OTYwNWRlMjYtYzA2Yy0xMWVhLWI2NTAtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "dHVubmVs"},
                            {"name": "action", "value": "YWRkdHVu"},
                            {"name": "id", "value": "YTBmOTBhNDktNGViMC1mMDRjLTNkYzgtN2IzMGE1YjQ1ZmNk"},
                            {"name": "srcid", "value": "NGFiMDExNTQtYzEyZS0xMWVhLWI5M2UtMDAwYzI5MTMwYjcx"},
                            {"name": "lhost", "value": "MTkyLjE2OC41Ny4xMDA="},
                            {"name": "lport", "value": "Nzc3Nw=="},
                            {"name": "dstid", "value": "NTJmMDI4ZDYtYzEyZS0xMWVhLWI4NDctMDAwYzI5MTMwYjcx"},
                            {"name": "rhost", "value": "MTkyLjE2OC41Ny4yMDA="},
                            {"name": "rport", "value": "NTU1NQ=="},
                            {"name": "enabled", "value": "dHJ1ZQ=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name":"module","value":"dHVubmVs"},
                            {"name":"action","value":"b3Blbg=="},
                            {"name":"id","value":"YTBmOTBhNDktNGViMC1mMDRjLTNkYzgtN2IzMGE1YjQ1ZmNk"},
                            {"name":"sessionid","value":"OGE3M2VkOTItYzEyZS0xMWVhLWIzZGUtMDAwYzI5MTMwYjcx"},
                            {"name":"dstid","value":"NTJmMDI4ZDYtYzEyZS0xMWVhLWI4NDctMDAwYzI5MTMwYjcx"},
                            {"name":"srcid","value":"NGFiMDExNTQtYzEyZS0xMWVhLWI5M2UtMDAwYzI5MTMwYjcx"},
                            {"name":"rhost","value":"MTkyLjE2OC41Ny4yMDA="},
                            {"name":"rport","value":"NTU1NQ=="}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name":"module","value":"dHVubmVs"},
                            {"name":"action","value":"b3Blbl9zdWNjZXNz"},
                            {"name":"id","value":"YTBmOTBhNDktNGViMC1mMDRjLTNkYzgtN2IzMGE1YjQ1ZmNk"},
                            {"name":"srcid","value":"NTJmMDI4ZDYtYzEyZS0xMWVhLWI4NDctMDAwYzI5MTMwYjcx"},
                            {"name":"dstid","value":"NGFiMDExNTQtYzEyZS0xMWVhLWI5M2UtMDAwYzI5MTMwYjcx"},
                            {"name":"sessionid","value":"OGE3M2VkOTItYzEyZS0xMWVhLWIzZGUtMDAwYzI5MTMwYjcx"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
        {
            "@timestamp": "2016-09-29T08:33:28",
            "network.transport": "TCP",
            "source.mac": "00:50:56:c0:00:08",
            "destination.mac": "00:0c:29:8a:3d:a7",
            "source.address": "192.168.43.1",
            "source.ip": "192.168.43.1",
            "destination.address": "192.168.43.135",
            "destination.ip": "192.168.43.135",
            "source.port": "50999",
            "destination.port": "12345",
            "websocket.masked": 1,
            "websocket.key": "b7:ce:fd:57",
            "websocket.masked_payload": "Masked payload",
            "websocket.payload": dumps(
                {
                    "children":
                        [
                            {"name": "module", "value": "dHVubmVs"},
                            {"name": "action", "value": "ZGF0YQ=="},
                            {"name": "id", "value": "YTBmOTBhNDktNGViMC1mMDRjLTNkYzgtN2IzMGE1YjQ1ZmNk"},
                            {"name": "sessionid", "value": "OGE3M2VkOTItYzEyZS0xMWVhLWIzZGUtMDAwYzI5MTMwYjcx"},
                            {"name": "dstid", "value": "NTJmMDI4ZDYtYzEyZS0xMWVhLWI4NDctMDAwYzI5MTMwYjcx"},
                            {"name": "srcid", "value": "NGFiMDExNTQtYzEyZS0xMWVhLWI5M2UtMDAwYzI5MTMwYjcx"},
                            {"name": "data", "value": "aGVsbG8K"}
                        ]
                }
            ),
            "network.protocol": [
                "eth",
                "ip",
                "tcp",
                "websocket",
                "data-text-lines"
            ]
        },
    ]


parameter_mapping = {
        "module": {
            "elk_field": "drovorub.module",
            "base64decode": True
        },
        "action": {
            "elk_field": "drovorub.action",
            "base64decode": True
        },
        "mode": {
            "elk_field": "drovorub.mode",
            "base64decode": True
        },
        "clientid": {
            "elk_field": "drovorub.clientid"
        },
        "serverid": {
            "elk_field": "drovorub.serverid"
        },
        "session_id": {
            "elk_field": "drovorub.session_id",
            "base64decode": True
        },
        "src_id": {
            "elk_field": "drovorub.src_id",
            "base64decode": True
        },
        "dst_id": {
            "elk_field": "drovorub.dst_id",
            "base64decode": True
        },
        "local_path": {
            "elk_field": "drovorub.local_path",
            "base64decode": True
        },
        "remote_id": {
            "elk_field": "drovorub.remote_id",
            "base64decode": True
        },
        "remote_path": {
            "elk_field": "drovorub.remote_path",
            "base64decode": True
        },
        "path": {
            "elk_field": "drovorub.path",
            "base64decode": True
        },
        "size": {
            "elk_field": "drovorub.size",
            "base64decode": True
        },
        "offset": {
            "elk_field": "drovorub.offset",
            "base64decode": True
        },
        "data": {
            "elk_field": "drovorub.data",
            "base64decode": True
        },
        "status": {
            "elk_field": "drovorub.status",
            "base64decode": True
        },
        "progress": {
            "elk_field": "drovorub.progress",
            "base64decode": True
        },
        "reason": {
            "elk_field": "drovorub.reason",
            "base64decode": True
        },
        "active": {
            "elk_field": "drovorub.active",
            "base64decode": True
        },
        "mask": {
            "elk_field": "drovorub.mask",
            "base64decode": True
        },
        "mon_id": {
            "elk_field": "drovorub.mon_id",
            "base64decode": True
        },
        "port": {
            "elk_field": "drovorub.port",
            "base64decode": True
        },
        "proto": {
            "elk_field": "drovorub.proto",
            "base64decode": True
        },
        "srcid": {
            "elk_field": "drovorub.src_id",
            "base64decode": True
        },
        "dstid": {
            "elk_field": "drovorub.dst_id",
            "base64decode": True
        },
        "lhost": {
            "elk_field": "drovorub.lhost",
            "base64decode": True
        },
        "lport": {
            "elk_field": "drovorub.lport",
            "base64decode": True
        },
        "rhost": {
            "elk_field": "drovorub.rhost",
            "base64decode": True
        },
        "rport": {
            "elk_field": "drovorub.rport",
            "base64decode": True
        },
        "enabled": {
            "elk_field": "drovorub.enabled",
            "base64decode": True
        }
}


def process_packet(p):
    # Initialize the packet record
    packetrecord = {
        "@timestamp": datetime.utcfromtimestamp(float(p.sniff_timestamp)).isoformat(),
        "network.transport": p.transport_layer
    }

    # Process each layer
    layer_names = []
    for packet_layer in p.layers:
        # print(dir(l))
        # Save the layer name into the list of layers
        layer_names.append(packet_layer.layer_name)

        # Switch on the layer name
        if packet_layer.layer_name == "eth":
            packetrecord["source.mac"] = packet_layer.src
            packetrecord["destination.mac"] = packet_layer.dst
        elif packet_layer.layer_name == "ip":
            packetrecord["source.address"] = packet_layer.src
            packetrecord["source.ip"] = packet_layer.src
            packetrecord["destination.address"] = packet_layer.dst
            packetrecord["destination.ip"] = packet_layer.dst
        elif packet_layer.layer_name == "tcp":
            packetrecord["source.port"] = packet_layer.port
            packetrecord["destination.port"] = packet_layer.dstport
        elif packet_layer.layer_name == "websocket":
            packetrecord["websocket.masked"] = int(packet_layer.mask)
            if packetrecord["websocket.masked"] != 0:
                packetrecord["websocket.key"] = packet_layer.get("masking_key")
                packetrecord["websocket.masked_payload"] = packet_layer.get("masked_payload")
        elif packet_layer.layer_name == "data-text-lines":
            # Make sure we have a websocket layer in the packet
            if "websocket" in layer_names:
                packetrecord["websocket.payload"] = packet_layer.get('')
        else:
            # This isn't the layer we are looking for
            pass

    # Add the layer names
    packetrecord["network.protocol"] = layer_names
    return packetrecord


def drovorub_enrich(packetrecord, drov_name_mapping):
    # Process the JSON structure
    try:
        json_packetrecord = loads(packetrecord.get("websocket.payload"))
        # Do a heuristic check for the expected c2 structure to look for a list embedded under the c2 string
        # todo: see if we want to limit this to just a key named children or leave it open for wider detection
        if len(json_packetrecord.keys()) == 1 and isinstance(json_packetrecord[next(iter(json_packetrecord.keys()))], list):
            for command_line in json_packetrecord[next(iter(json_packetrecord.keys()))]:
                try:
                    if command_line.get("name") in drov_name_mapping.keys():
                        if drov_name_mapping[command_line.get("name")].get("base64decode") is True:
                            packetrecord[drov_name_mapping[command_line.get("name")].get("elk_field")] = b64decode(command_line.get("value")).decode("ascii")
                        else:
                            packetrecord[drov_name_mapping[command_line.get("name")].get("elk_field")] = command_line.get("value")
                except binascii.Error:
                    # This will catch incorrect base64 padding
                    print_exc()

    except ValueError as e:
        pass

    return packetrecord


def bulk_to_elasticsearch(es, bulk_queue):
    try:
        helpers.bulk(es, bulk_queue)
        return True
    except:
        print(print_exc())
        return False


def main_packet_loop(packet):
    pass


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("elk_ip", help="Elasticsearch host to connect to")
    parser.add_argument("elk_index", help="Index to search")
    command_options = parser.add_mutually_exclusive_group(required=True)
    command_options.add_argument("-pcap", help="Pcap file to analyst", default="")
    command_options.add_argument("-live", help="Network interface to listen on", default="")
    command_options.add_argument("-test", action="store_true", help="Load test data", default=False)
    parser.add_argument("-elk_un", help="ELK username", default=None)
    parser.add_argument("-elk_pw", help="ELK username", default=None)
    parser.add_argument("-bufferlen", help="Maximum buffer length in packet records before sending data to ELK", default=500)
    parser.add_argument("-buffertime", help="Maximum buffer time in seconds before sending data to ELK", default=1)
    args = parser.parse_args()

    if args.elk_un is not None and args.elk_pw is not None:
        es = Elasticsearch(
            [args.elk_ip],
            http_auth=(args.elk_un, args.elk_pw),
            scheme="https",
            verify_certs=False
        )
    else:
        es = Elasticsearch([args.elk_ip])

    data_buffer = []
    last_buffer_time = time()

    if args.test is True:
        for p in test_data:
            packet_data = p

            # Enrich the packet data
            packet_data = drovorub_enrich(packet_data, drov_name_mapping=parameter_mapping)

            # Add the elastic index
            packet_data["_index"] = args.elk_index

            # Queue the packet data for storage
            data_buffer.append(packet_data)

            # Check to see if buffer conditions have been met
            if len(data_buffer) > args.bufferlen:
                print("Bulking data to ELK: " + str(len(data_buffer)))
                # Cache data into ELK
                bulk_to_elasticsearch(es, data_buffer)

                # Reset the buffer and buffer time
                last_buffer_time = time()
                data_buffer = []
    elif args.pcap is not "":
        for p in FileCapture(args.pcap, display_filter="websocket"):
            packet_data = process_packet(p)

            # Enrich the packet data
            packet_data = drovorub_enrich(packet_data, drov_name_mapping=parameter_mapping)

            # Add the elastic index
            packet_data["_index"] = args.elk_index

            # Queue the packet data for storage
            data_buffer.append(packet_data)

            # Check to see if buffer conditions have been met
            if len(data_buffer) > args.bufferlen:
                print("Bulking data to ELK: " + str(len(data_buffer)))
                # Cache data into ELK
                bulk_to_elasticsearch(es, data_buffer)

                # Reset the buffer and buffer time
                last_buffer_time = time()
                data_buffer = []
    elif args.live is not "":
        for p in LiveCapture(interface=args.live, display_filter="websocket"):
            # Extract the packet data from the wire
            packet_data = process_packet(p)

            # Enrich the packet data
            packet_data = drovorub_enrich(packet_data, drov_name_mapping=parameter_mapping)

            # Add the elastic index
            packet_data["_index"] = args.elk_index

            # Queue the packet data for storage
            data_buffer.append(packet_data)

            # Check to see if buffer conditions have been met
            if len(data_buffer) > args.bufferlen or \
                    ((time() - last_buffer_time > args.buffertime) and len(data_buffer) > 0):
                print("Bulking data to ELK: " + str(len(data_buffer)))
                # Cache data into ELK
                bulk_to_elasticsearch(es, data_buffer)

                # Reset the buffer and buffer time
                last_buffer_time = time()
                data_buffer = []

    # Cache remaining data into ELK
    if len(data_buffer) > 0:
        print("Bulking final data to ELK: " + str(len(data_buffer)))
        bulk_to_elasticsearch(es, data_buffer)
