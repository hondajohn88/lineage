from __future__ import absolute_import
from __future__ import print_function

import re
import sys

import requests

from rtmbot.core import Plugin
from plugins.db import DataStore


class Silly(Plugin):
    def get_catfact(self):
        data = requests.get("http://catfacts-api.appspot.com/api/facts")
        if data.status_code == 200:
            return data.json()['facts'][0]
        return 'error getting fact!'

    def process_message(self, data):
        message = data['text']
        if 'groot' in message.lower():
            self.outputs.append([data['channel'], 'I AM GROOT'])
        if 'catfact' in message.lower():
            self.outputs.append([data['channel'], self.get_catfact()])
