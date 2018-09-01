from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import re
import sys
from itertools import islice

from jira import JIRA, JIRAError

from rtmbot.core import Plugin

from plugins.db import DataStore

class JiraProxy(object):
    def __init__(self):
        config = DataStore.get("JIRA", "config")
        if not config:
            print("JIRA config missing, please add with:")
            print("DataStore.put('JIRA', 'config', {'url': '', 'username': '', 'password': ''})")
            sys.exit(1)
        basic_auth=(config['username'], config['password'])
        self.jira = JIRA(config['url'], basic_auth=(config['username'], config['password']))

jira = JiraProxy().jira

class JiraTicketParser(Plugin):
    def process_message(self, data):
        valid_prefixes = ['ANNOUNCE', 'BUGBASH', 'DEVREL', 'INFRA', 'LINEAGE', 'LINN', 'REGRESSION']
        text = data['text']
        if re.search(r'\bignore\b', text):
            return False
        match_iter = re.finditer(r'[A-Z]+-[0-9]+', text)
        for match in islice(match_iter, 4):
            ticket = match.group(0)
            if any(ticket.startswith(item) for item in valid_prefixes):
                try:
                    issue = jira.issue(ticket)
                except JIRAError as j:
                    return
                self.slack_client.api_call('chat.postMessage', channel=data['channel'], as_user=True, attachments=[
                    {"fallback": "https://jira.lineageos.org/browse/{}: {}".format(ticket, issue.fields.summary), "color": "good", "title": "JIRA: {}".format(ticket), "title_link": "https://jira.lineageos.org/browse/{}".format(ticket), 'text': "Summary: {}\nStatus: {}\nAssignee: {}".format(issue.fields.summary, issue.fields.status.name, issue.fields.assignee)}
                ])

class JiraAnnounceSync(Plugin):
    def process_message(self, data):
        if data['channel'] == 'C3D4N6Q9L':
            if data['text'].lower().startswith('announcement: '):
                who = self.slack_client.api_call('users.info', user=data['user'])['user']['name']
                j = jira.create_issue(project="ANNOUNCE", issuetype='Task', summary='New slack announcement from {}'.format(who), description=data['text'])
