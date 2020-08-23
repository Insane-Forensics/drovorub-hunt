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

from requests import put
from json import dumps
from requests.auth import HTTPBasicAuth
from argparse import ArgumentParser

drovorub_mapping = {
  "mappings": {
    "properties": {
      "network.protocol": "keyword",
      "network.transport": "keyword",
      "source.address": "ip",
      "source.ip": "ip",
      "source.mac": "keyword",
      "source.port": "long",
      "destination.address": "ip",
      "destination.ip": "ip",
      "destination.mac": "keyword",
      "destination.port": "long",
      "websocket.masked": "boolean",
      "websocket.key": "keyword",
      "websocket.payload": {
        "type": "text",
        "fields" : {
          "raw": {
            "type" : "keyword"
          }
        }
      },
      "websocket.masked_payload": {
        "type": "text",
        "fields" : {
          "raw": {
            "type" : "keyword"
          }
        }
      },
      "drovorub.module": "keyword",
      "drovorub.action": "keyword",
      "drovorub.mode": "keyword",
      "drovorub.clientid": "keyword",
      "drovorub.serverid": "keyword",
      "drovorub.session_id": "keyword",
      "drovorub.src_id": "keyword",
      "drovorub.dst_id": "keyword",
      "drovorub.local_path": "keyword",
      "drovorub.remote_id": "keyword",
      "drovorub.remote_path": "keyword",
      "drovorub.path": "keyword",
      "drovorub.size": "keyword",
      "drovorub.offset": "keyword",
      "drovorub.data": "keyword",
      "drovorub.status": "keyword",
      "drovorub.progress": "keyword",
      "drovorub.reason": "keyword",
      "drovorub.active": "keyword",
      "drovorub.mask": "keyword",
      "drovorub.mon_id": "keyword",
      "drovorub.port": "keyword",
      "drovorub.proto": "keyword",
      "drovorub.src_id": "keyword",
      "drovorub.dst_id": "keyword",
      "drovorub.lhost": "ip",
      "drovorub.lport": "keyword",
      "drovorub.rhost": "ip",
      "drovorub.rport": "keyword",
      "drovorub.enabled": "keyword",
      "@timestamp": "date"
    }
  }
}

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("elk_ip", help="Elasticsearch host to connect to")
    parser.add_argument("elk_index", help="Index to search")
    parser.add_argument("-elk_un", help="ELK username", default=None)
    parser.add_argument("-elk_pw", help="ELK username", default=None)
    parser.add_argument("-elk_bufferlen", help="Length of ELK buffer before writing", default=1000)
    parser.add_argument('-meta', help="Metadata to insert with elastic record", default="{}")
    args = parser.parse_args()

    headers = {
        'Content-Type': 'application/json'
    }
    url_index = args.elk_ip + "/" + args.elk_index + "?pretty"
    print("connecting to: " + url_index)
    if args.elk_un is not None and args.elk_pw is not None:
        space_status = put(url=url_index, data=dumps(drovorub_mapping), headers=headers, auth=HTTPBasicAuth(args.elk_un, args.elk_pw), verify=False)
    else:
        space_status = put(url=url_index, data=dumps(drovorub_mapping), headers=headers)

    print("Index created with status: " + str(space_status.status_code) + " -> " + str(space_status.text))