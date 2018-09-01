from __future__ import absolute_import
from __future__ import print_function

import re
import sys
from itertools import islice

import requests

from rtmbot.core import Plugin

class CveParser(Plugin):

    def process_message(self, data):
        message = data['text']
        if re.search(r'\bignore\b', message):
            return False
        match_iter = re.finditer(r'CVE-\d{4}-\d{4,7}', message)
        for match in islice(match_iter, 4):
            cve = match.group(0)
            r = requests.get("https://cve.circl.lu/api/cve/{}".format(cve))
            if r.status_code == 200:
                try:
                    summary = r.json()['summary']
                    url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={}".format(cve)
                    self.slack_client.api_call('chat.postMessage', channel=data['channel'], as_user=True, attachments=[
                        {"fallback": "{}: {} ({})".format(cve, summary, url), "color": "danger", "title": "{}: {}".format(cve, summary), "title_link": url}
                    ])
                except:
                    pass
