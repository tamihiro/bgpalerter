# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# Licensed under BSD 3-Clause License. See LICENSE for more details.

import yaml
import smtplib
from bgpalerter import BGPalerter
import sys
import os
import http.client
from urllib.parse import urlparse
import json
from email.mime.text import MIMEText
import logging
from functools import partial

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s (%(levelname)-8s) (%(threadName)-10s) %(message)s',
                    filename=os.getcwd() + '/' + os.path.basename(os.path.dirname(os.path.abspath(__file__))) + '.log',
                    filemode='a')

config = yaml.safe_load(open("config.yml", "r").read())


to_be_monitored = {}

for file_name in config.get("monitored-prefixes-files"):
    logging.info("Loading prefixes from " + file_name)
    pointer = open(file_name, "r")
    input_list = yaml.safe_load(pointer.read())
    for item in input_list.keys():
        to_be_monitored[item] = input_list[item]

def send_to_slack(message, message_color="good"):
    try:
        msg = dict()
        msg['text'] = ""
        msg['attachments'] = [ dict([('color', message_color), ('text', message), ('fallback', ''), ]) ]
        parsed_url = urlparse(config.get("slack-web-hook"))
        if config.get("proxy-host") and config.get("proxy-port"):
            conn = http.client.HTTPSConnection(config.get("proxy-host"), config.get("proxy-port"), timeout=10)
            conn.set_tunnel(parsed_url.netloc, 443)
        else:
            conn = http.client.HTTPSConnection(parsed_url.netloc, timeout=10)
        conn.request("POST", parsed_url.path, json.dumps(msg))
        response = conn.getresponse()
        if response.status!=200:
            logging.error("send_to_slack() failed: [{}][{}]".format(response.status, response.msg))
        conn.close()
    except:
        logging.error("send_to_slack() threw exception: {}".format(sys.exc_info()[1]))

def send_email(message):
    email_from = config.get("sender-notifications-email")
    email_to = config.get("notified-emails")

    msg = MIMEText(message)
    msg['Subject'] = 'BGP alert'
    msg['From'] = email_from
    msg['To'] = ", ".join(email_to)

    server = smtplib.SMTP('localhost')
    server.sendmail(email_from, email_to, msg.as_string())
    server.quit()

def send_to_log(message, log_method=logging.debug):
    log_method("{}".format(message))

send_to_log("Starting to monitor...", log_method=logging.info)
#send_to_slack("Starting to monitor...", message_color="good")
# send_email("Starting to monitor...")

# change the way you want to be notified below
alerter = BGPalerter(config)

alerter.on("hijack", partial(send_to_slack, message_color="danger"))
alerter.on("hijack", partial(send_to_log, log_method=logging.warning))
alerter.on("low-visibility", partial(send_to_slack, message_color="warning"))
alerter.on("low-visibility", partial(send_to_log, log_method=logging.warn))
alerter.on("difference", partial(send_to_slack, message_color="warning"))
# alerter.on("heartbeat", send_to_slack)
alerter.on("error", partial(send_to_log, log_method=logging.error))

alerter.monitor(to_be_monitored)
