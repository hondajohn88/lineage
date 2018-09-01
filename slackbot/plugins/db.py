from __future__ import print_function
from __future__ import unicode_literals

from datetime import datetime
from mongoengine import connect, Document, StringField, DateTimeField

import json

class _Data(Document):
    plugin = StringField(required=True)
    key = StringField(required=True, unique_with="plugin")
    value = StringField(required=True)
    date = DateTimeField(default=datetime.now)

connect("slackbot")

class DataStore(object):

    @classmethod
    def get(cls, plugin, key, default=None):
        '''Given a key, get its value'''
        data = _Data.objects(plugin=plugin, key=key).first()
        if data:
            return json.loads(data.value)
        else:
            return default

    @classmethod
    def save(cls, plugin, key, value):
        '''Takes a key:val pair and stores it
           value can be anything that is json serializable
        '''
        data = _Data.objects(plugin=plugin, key=key).first()
        if data:
            data.value = json.dumps(value)
            data.save()
        else:
            data = _Data(plugin=plugin, key=key, value=json.dumps(value)).save()
        return True

    @classmethod
    def delete(cls, plugin, key):
        '''Takes a key and deletes it'''
        data = _Data.objects(plugin=plugin, key=key)
        if data:
            data.delete()
            return True
        else:
            return False
