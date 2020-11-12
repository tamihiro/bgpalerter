# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# Licensed under BSD 3-Clause License. See LICENSE for more details.

import sys
import os
import json
import re
import websocket
import ipaddress
import threading
import logging

class RisListener:

    def __init__(self, url, proxy_host, proxy_port):
        self.prefixes = {}
        self.url = url
        self.proxy_host = proxy_host or None
        self.proxy_port = proxy_port or 0
        self.prefixes_index = {
            "4": [],
            "6": [],
        }
        self.hijacks = {}
        self.callbacks = {
            "hijack": [],
            "withdrawal": [],
            "announcement": [],
            "difference": [],
            "error": []
        }

        ws = websocket.WebSocket()
        self.ws = ws
        self._closed = True
        self._connect()

        def ping():
            threading.Timer(5, ping).start()
            try:
                self.ws.send(json.dumps({
                    "type": "ping",
                    #"data": {}
                    }))
            except:
                if not self._closed:
                    logging.error("{}: {}: shutting down websocket connection..".format(self.__class__.__name__, sys.exc_info()[1]))
                    try:
                        self.ws.shutdown()
                    except:
                        pass
                if not self.ws.connected:
                    logging.warning("{}: websocket connection closed.".format(self.__class__.__name__))
                    if not self._closed:
                        self._closed = True

        ping()

    def _connect(self):
        if self.proxy_host and self.proxy_port:
            logging.info("{}: using proxy for websocket connection {}:{}".format(self.__class__.__name__, self.proxy_host, self.proxy_port, ))
        for n in range(1, 11):
            try:
                self.ws.connect(self.url, timeout=3, http_proxy_host=self.proxy_host, http_proxy_port=self.proxy_port, )
            #except (websocket._exceptions.WebSocketTimeoutException, websocket._exceptions.WebSocketProxyException) as e:
            #    logging.warning("{}: websocket connect timedout. [{}]".format(self.__class__.__name__, n))
            except:
                logging.warning("{}: {} [{}]".format(self.__class__.__name__, sys.exc_info()[1], n))
                continue
            if self.ws.connected:
                logging.info("{}: websocket connection established.".format(self.__class__.__name__))
                self._closed = False
                return
        logging.critical("{}: websocket connect failed, exiting...".format(self.__class__.__name__))
        os._exit(os.EX_TEMPFAIL)

    def _reconnect(self):
        while self.ws.connected:
            self.ws.shutdown()
        logging.info("{}: websocket connection closed.".format(self.__class__.__name__))
        self._connect()
        
    def on(self, event, callback):
        if event not in self.callbacks:
            raise Exception('This is not a valid event: ' + event)
        else:
            self.callbacks[event].append(callback)

    def _detect_hijack(self, original_prefix, original_as, hijacked_prefix, hijacking_as, peer, description):
        if hijacking_as and hijacking_as != original_as:
            for call in self.callbacks["hijack"]:
                call({
                    "expected": {
                        "originAs": original_as,
                        "prefix": original_prefix
                    },
                    "altered": {
                        "originAs": hijacking_as,
                        "prefix": hijacked_prefix
                    },
                    "description": description,
                    "peer": peer
                })
        elif hijacked_prefix != original_prefix:
            for call in self.callbacks["difference"]:
                call({
                    "expected": {
                        "prefix": original_prefix
                    },
                    "altered": {
                        "prefix": hijacked_prefix
                    },
                    "originAs": original_as,
                    "description": description,
                    "peer": peer
                })

    def _filter_visibility(self, item):
        str_prefix = item["prefix"]
        peer = item["peer"]
        prefix = ipaddress.ip_network(str_prefix)
        same_version_prefix_index = self.prefixes_index[str(prefix.version)]

        if prefix in same_version_prefix_index:
            logging.info("{}: withdrawal: {}".format(self.__class__.__name__, item))
            for call in self.callbacks["withdrawal"]:
                call({
                    "prefix": str_prefix,
                    "peer": peer
                })

    def _filter_announcement(self, item):
        str_prefix = item["prefix"]
        peer = item["peer"]
        path = item["path"]
        next_hop = item["next_hop"]
        prefix = ipaddress.ip_network(str_prefix)
        same_version_prefix_index = self.prefixes_index[str(prefix.version)]

        if prefix in same_version_prefix_index:
            for call in self.callbacks["announcement"]:
                call({
                    "prefix": str_prefix,
                    "peer": peer,
                    "path": path,
                    "next_hop": next_hop
                })

    def _filter_hijack(self, item):
        str_prefix = ""
        try:
            str_prefix = item["prefix"]
        except:
            logging.debug("{}: {}".format(self.__class__.__name__, item))
        prefix = ipaddress.ip_network(str_prefix)

        same_version_prefix_index = self.prefixes_index[str(prefix.version)]
        peer = item["peer"]
        path = item["path"]

        if len(path) > 0:
            origin_as = path[-1]

            if prefix in same_version_prefix_index:
                return self._detect_hijack(str_prefix, self.prefixes[str_prefix]["origin"], str_prefix, origin_as,
                                           peer, self.prefixes[str_prefix]["description"])
            else:
                for supernet in same_version_prefix_index:
                    if prefix.subnet_of(supernet):
                        if self.prefixes[str(supernet)]["monitor_more_specific"]:
                            return self._detect_hijack(str(supernet), self.prefixes[str(supernet)]["origin"], str_prefix,
                                                       origin_as, peer, self.prefixes[str(supernet)]["description"])

        return  # nothing strange

    def unpack(self, json_data):
        data = json_data["data"]
        unpacked = []

        if "announcements" in data:
            for announcement in data["announcements"]:
                next_hop = announcement["next_hop"]
                if "prefixes" in announcement:
                    for prefix in announcement["prefixes"]:
                        unpacked.append({
                            "type": "announcement",
                            "prefix": prefix,
                            "peer": data["peer"],
                            "path": data["path"],
                            "next_hop": next_hop
                        })

        if "withdrawals" in data:
            for prefix in data["withdrawals"]:
                unpacked.append({
                    "type": "withdrawal",
                    "prefix": prefix,
                    "peer": data["peer"]

                })

        return unpacked

    def subscribe(self, prefixes):
        self.prefixes = prefixes
        ip_list = list(map(ipaddress.ip_network, self.prefixes.keys()))

        self.prefixes_index = {
            "4": list(filter(lambda ip: ip.version == 4, ip_list)),
            "6": list(filter(lambda ip: ip.version == 6, ip_list)),
        }

        while True:
            if self._closed:
                self._reconnect()

            try:
                for prefix in prefixes:
                    logging.info("{}: Subscribing to {}".format(self.__class__.__name__, prefix))
                    self.ws.send(json.dumps({
                        "type": "ris_subscribe",
                        "data": {
                            "prefix": prefix,
                            "moreSpecific": True,
                            "type": "UPDATE",
                            "socketOptions": {
                                "includeRaw": False
                            }
                        }
                    }))

                for data in self.ws:
                    try:
                      json_data = json.loads(data)
                    except json.decoder.JSONDecodeError:
                      """
                      2020-11-02 
                      There has been an unnoticed change in the response message from '{"type": "pong","data":null}' to '{"type": "pong","data":undefined}' 
                      which results in JSONDdcodeError.
                      """
                      if re.match(r'{"type": "pong",', data):
                        continue
                      else:
                        logging.error("{}: {}: reconnecting..".format(self.__class__.__name__, sys.exc_info()[1]))
                        self._closed = True
                        break
                    if "type" in json_data:
                        
                        if json_data["type"] == "ris_error":
                            for call in self.callbacks["error"]:
                                call(json_data)

                        if json_data["type"] == "ris_message":
                            for parsed in self.unpack(json_data):
                                if parsed["type"] is "announcement":
                                    logging.debug("{}: announcement: {}".format(self.__class__.__name__, parsed))
                                    self._filter_hijack(parsed)
                                    self._filter_announcement(parsed)
                                elif parsed["type"] is "withdrawal":
                                    self._filter_visibility(parsed)
                        if json_data["type"] == "pong":
                            logging.debug("{}: {}".format(self.__class__.__name__, data))
            #except (websocket._exceptions.WebSocketConnectionClosedException, websocket._exceptions.WebSocketTimeoutException, ConnectionResetError) as e:
            except:
                logging.error("{}: {}: reconnecting..".format(self.__class__.__name__, sys.exc_info()[1]))
                self._closed = True

