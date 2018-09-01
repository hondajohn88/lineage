from __future__ import print_function
from __future__ import unicode_literals

import praw

from rtmbot.core import Plugin, Job

from db import DataStore

PLUGIN = 'reddit'

class RedditJob(Job):
    def run(self, slack_client):
        posts = []
        done = DataStore.get(PLUGIN, "done")
        if not done:
            done = []
            DataStore.save(PLUGIN, "done", done)
            print('saving empty done')
        try:
            r = praw.Reddit(user_agent="LineageOS Slack Bot v1.0")
            r.read_only = True
            for post in r.subreddit("lineageos").new(limit=10):
                if post.id in done:
                    continue
                posts.append(["C62RNKJTZ", "https://www.reddit.com" + post.permalink])
                done.append(post.id)
                DataStore.save(PLUGIN, "done", done)
        except Exception as e:
            print(e)
            pass
        return posts

class RedditPlugin(Plugin):

    def register_jobs(self):
        job = RedditJob(60)
        self.jobs.append(job)
