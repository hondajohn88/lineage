from __future__ import print_function
from bs4 import BeautifulSoup
from rtmbot.core import Plugin, Job

import base64
import requests

from plugins.db import DataStore

PLUGIN = 'tags'
PREFIX = '!'

CHANNEL = '#releases'
TAG_LIST_URL = 'https://android.googlesource.com/platform/build/+refs'
TAG_VIEW_URL = 'https://android.googlesource.com/platform/manifest/+/'
BUILD_ID_URL = 'https://android.googlesource.com/platform/build/+/%s/core/build_id.mk?format=TEXT'
JOB_DELAY = 300
class TagPlugin(Plugin):
    def register_jobs(self):
        job = TagJob(JOB_DELAY)
        self.jobs.append(job)

    def process_message(self, data):
        arg = data['text'].split()
        if arg[0] != PREFIX + 'tag':
            return
        if len(arg) != 2:
            self.outputs.append([data['channel'], 'Need exactly one tag.'])
            return

        tag = arg[1]
        if not tag.startswith('android') and not tag.startswith('snap'):
            tag = 'android-' + tag

        bid = TagJob._get_version(tag)
        if bid == 'unknown':
            self.outputs.append([data['channel'], 'Couldn\'t get build ID for ' + tag])
        else:
            self.outputs.append([data['channel'], tag + ': ' + bid])

class TagJob(Job):
    def __init__(self, *args, **kwargs):
        Job.__init__(self, *args, **kwargs)
        self.tags = DataStore.get(PLUGIN, "tags")
        if not self.tags:
            self.tags = self._get_tags()
            DataStore.save(PLUGIN, "tags", self.tags)

    def _get_tags(self):
        try:
            soup = BeautifulSoup(requests.get(TAG_LIST_URL).text, 'html.parser')
        except Exception as e:
            print('Error:', e)
            return []

        objs = soup.find_all(class_='RefList')
        tag_list = None
        for o in objs:
            if o.h3.string.lower() == 'tags':
                tag_list = o.ul
                break

        if tag_list is None:
            print('no tags found')
            return []

        res = []
        for o in tag_list.find_all('a'):
            res.append(o.string)
        print("Loaded %d refs"%len(res))
        return res

    @staticmethod
    def _get_version(tag):
        print(tag)
        try:
            text = base64.b64decode(requests.get(BUILD_ID_URL%tag).text)
        except Exception as e:
            return 'unknown'
        return text[text.index('BUILD_ID='):].split('\n')[0].strip().split('=')[1]

    def run(self, slack_client):
        new_tags = self._get_tags()
        if len(self.tags) == 0:
            self.tags = new_tags
            DataStore.save(plugin, "tags", self.tags)
            return []
        # note: this won't catch tags that are removed
        diff = set(new_tags) - set(self.tags)
        if len(diff) > 0:
            msgs = []
            for tag in sorted(diff):
                bid = TagJob._get_version(tag)
                msgs.append('<%s%s|%s> - %s'%(TAG_VIEW_URL, tag, tag, bid))
            self.tags = new_tags
            DataStore.save(plugin, "tags", self.tags)
            for m in msgs:
                print(m)
                slack_client.api_call('chat.postMessage', as_user=True,
                        channel=CHANNEL, text=m)
        return []
