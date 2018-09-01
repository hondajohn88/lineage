from __future__ import print_function
from mongoengine import *

from rtmbot.core import Plugin
from datetime import datetime
from random import SystemRandom

import string
from db import DataStore

_random = SystemRandom()

def random_string(size=5, chars=string.ascii_lowercase + string.digits):
    return ''.join(_random.choice(chars) for j in range(size))

class Vote:
    def __init__(self, pollid=None, user=None, choice=None):
        self.p = pollid
        self.u = user
        self.c = choice

    @staticmethod
    def load(d):
        v = Vote()
        v.__dict__ = d
        return v

class Poll:
    def __init__(self, name=None, pollid=None, owner=None, options=None):
        self.n = name
        self.i = pollid
        self.u = owner
        self.o = options or []

    @staticmethod
    def load(d):
        p = Poll()
        p.__dict__ = d
        return p

PLUGIN = 'poll'
PREFIX = '!'

class PollPlugin(Plugin):
    def __init__(self, slack_client, plugin_config):
        Plugin.__init__(self, "poll", slack_client, plugin_config)
        self.polls = {}
        self.votes = {}
        self._load()

    def _save_votes(self):
        tmp = {k: {j: self.votes[k][j].__dict__ for j in self.votes[k]} for k in self.votes}
        DataStore.save(PLUGIN, 'votes', tmp)

    def _save_poll(self):
        tmp = {k: self.polls[k].__dict__ for k in self.polls}
        DataStore.save(PLUGIN, 'polls', tmp)

    def _save(self):
        self._save_poll()
        self._save_votes()

    def _load(self):
        data = DataStore.get(PLUGIN, 'votes', {})
        for d in data.values(): # for each poll
            for k in d: # for each user
                d[k] = Vote.load(d[k])
        self.votes = data
        print(data)
        data = DataStore.get(PLUGIN, 'polls', {})
        for k,v in data.items():
            self.polls[k] = Poll.load(v)
        print(self.polls)

    def is_owner(self, user, pollid):
        if pollid not in self.polls:
            return False
        return self.polls[pollid].u == user

    def poll_create(self, name, owner):
        pollid = random_string()
        p = Poll(name, pollid, owner)
        self.polls[pollid] = p
        self.votes[pollid] = {}
        self._save()
        return pollid

    def poll_vote(self, user, pollid, choice):
        if pollid not in self.polls:
            return False
        if choice >= len(self.polls[pollid].o):
            return False
        v = Vote(pollid, user, choice)
        self.votes[pollid][user] = v
        self._save_votes()
        return True

    def poll_unvote(self, user, pollid):
        if pollid not in self.polls:
            return False
        del self.votes[pollid][user]
        self._save_votes()
        return True

    def poll_delete(self, pollid):
        if pollid not in self.polls:
            return False
        del self.polls[pollid]
        del self.votes[pollid]
        self._save()
        return True

    def poll_add_option(self, user, pollid, option):
        if pollid not in self.polls:
            return False
        if not self.is_owner(user, pollid):
            return False
        self.polls[pollid].o.append(option)
        self._save_poll()
        return True

    def poll_get_results(self, pollid):
        if pollid not in self.polls:
            return False
        if len(self.polls[pollid].o) == 0:
            return []
        res = [0] * len(self.polls[pollid].o)
        for el in self.votes[pollid].values():
            res[el.c] += 1
        return res

    def poll_get_name(self, pollid):
        if pollid not in self.polls:
            return False
        return self.polls[pollid].n

    def poll_get_options(self, pollid):
        if pollid not in self.polls:
            return False
        if len(self.polls[pollid].o) == 0:
           return []
        return self.polls[pollid].o

    def get_polls(self):
        res = []
        for poll in self.polls:
            res.append((self.polls[poll].n, self.polls[poll].i))
        return res

    def _say(self, data, message):
        print(message)
        self.outputs.append([data['channel'], message])

    def process_message(self, data):
        arg = data['text'].split()
        if arg[0] != PREFIX + 'poll':
            return
        if len(arg) == 1 or arg[1] == 'help':
            commands = [
                    'create <poll question> - create a poll with the given question. responds with the new poll\'s id',
                    'choice <pollid> <new poll option> - add <new poll option> to the list of options for <pollid>',
                    'choices <pollid> - list available choices for <pollid>',
                    'vote <pollid> <option number> - vote for <option number> in <pollid>. If you already voted, transfer your vote',
                    'unvote <pollid> - remove your vote from <pollid>',
                    'results <pollid> - show results for <pollid>',
                    'list - show all active polls',
                    'delete <pollid> - delete a poll question'
                    ]
            att = []
            for c in commands:
                att.append({'text': c})
            self.slack_client.api_call('chat.postMessage', text='poll subcommands:',
                    channel=data['channel'], as_user=True, attachments=att)
            return
        cmd = arg[1]
        if cmd == 'create':
            # !poll create <poll question>
            if len(arg) < 3:
                self._say(data, 'not enough arguments')
                return
            newid = self.poll_create(' '.join(arg[2:]), data['user'])
            self._say(data, 'Poll created: ' + newid)
        elif cmd == 'choice':
            # !poll choice <pollid> <text>
            if len(arg) < 4:
                self._say(data, 'not enough arguments')
                return

            self.poll_add_option(data['user'], arg[2], ' '.join(arg[3:]))
            self._say(data, 'added')

        elif cmd == 'vote':
            # !poll vote <pollid> <number>
            if len(arg) < 4:
                self._say(data, 'not enough arguments')
                return


            if not self.poll_vote(data['user'], arg[2], int(arg[3])):
                self._say(data, 'vote failed')
                return
            self._say(data, 'voted')

        elif cmd == 'unvote':
            # !poll unvote <pollid>
            if len(arg) < 3:
                self._say(data, 'not enough arguments')
                return

            self.poll_unvote(data['user'], arg[2])
            self._say(data, 'unvoted')

        elif cmd == 'delete':
            # !poll delete <pollid>
            if len(arg) < 3:
                self._say(data, 'not enough arguments')
                return
            self.poll_delete(arg[2])
            self._say(data, 'deleted')

        elif cmd == 'choices':
            # !poll options <pollid>
            if len(arg) < 3:
                self._say(data, 'not enough arguments')
                return
            opt = self.poll_get_options(arg[2])
            i = 0
            attachments = []
            for o in opt:
                attachments.append({
                    'fallback': '%d. %s'%(i, o),
                    'text': '%d. %s'%(i, o)
                })
                i += 1
            name = self.poll_get_name(arg[2])
            if len(attachments) == 0:
                attachments.append({'text': 'No options!', 'color': 'danger'})
            self.slack_client.api_call('chat.postMessage', text='Poll: %s'%name,
                    channel=data['channel'], as_user=True, attachments=attachments)
        elif cmd == 'list':
            # !poll list - show polls
            polls = self.get_polls()
            attachments = []
            for poll in polls:
                attachments.append({
                    'text': '%s (%s)'%poll
                })
            self.slack_client.api_call('chat.postMessage', text='All polls:',
                channel=data['channel'], as_user=True, attachments=attachments)

        elif cmd == 'results':
            # !poll results <pollid> - shows poll status
            res = self.poll_get_results(arg[2])
            opt = self.poll_get_options(arg[2])
            obj = zip(opt, res) # obj is a dict of option => votes
            attachments = []
            for pair in sorted(dict(obj).items(), key=lambda a:a[1], reverse=True):
                attachments.append({
                    'text': '%s - %d votes'%(pair[0], pair[1])
                    })
            name = self.poll_get_name(arg[2])
            if len(attachments) == 0:
                attachments.append({'text': 'No options!', 'color': 'danger'})
            self.slack_client.api_call('chat.postMessage', text='Poll: %s'%name,
                    channel=data['channel'], as_user=True, attachments=attachments)
        else:
            self._say(data, 'unknown cmd %s'%cmd)
