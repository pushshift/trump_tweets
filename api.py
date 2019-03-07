#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import ujson as json
import time
from datetime import datetime
import math
import configparser
import requests
from collections import deque,defaultdict
from requests_oauthlib import OAuth1
import sys,os

class Api:

    def __init__(self):

        self.queue = deque()
        self.ratelimit_reset = None
        self.ratelimit_remaining = None
        self.url_counter = defaultdict(int)
        self.base_url = 'https://api.twitter.com/'
        self.last_time_scanned = None

        # Read Credentials
        Config = configparser.ConfigParser()
        Config.read("credentials.ini")
        consumer_key = Config.get("TwitterCredentials","consumer_key")
        consumer_secret = Config.get("TwitterCredentials","consumer_secret")
        access_token = Config.get("TwitterCredentials","access_token")
        access_token_secret = Config.get("TwitterCredentials","access_token_secret")

        self.auth_objs = [] # This list contains all the authorization accounts

        self.auth_objs.append({'type':'user',
                                'consumer_key':consumer_key,
                                'consumer_secret':consumer_secret,
                                'access_token':access_token,
                                'access_token_secret':access_token_secret,
                                'rate_limit_remaining': defaultdict(int),
                                'rate_limit_reset': defaultdict(int)
                                })

        self.auth_objs.append({'type':'app',
                                'consumer_key':consumer_key,
                                'consumer_secret':consumer_secret,
                                'token': self.get_token(consumer_key,consumer_secret),
                                'rate_limit_remaining': defaultdict(int),
                                'rate_limit_reset': defaultdict(int)
                                })

    def get_token(self,consumer_key,consumer_secret):
        key_secret = '{}:{}'.format(consumer_key,consumer_secret).encode('ascii')
        b64_encoded_key = base64.b64encode(key_secret).decode('ascii')
        base_url = 'https://api.twitter.com/'
        auth_url = '{}oauth2/token'.format(base_url)
        auth_headers = {
        'Authorization': 'Basic {}'.format(b64_encoded_key),
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }
        auth_data = {'grant_type': 'client_credentials'}

        auth_resp = requests.post(auth_url,headers=auth_headers,data=auth_data)
        access_token = auth_resp.json()['access_token']
        return access_token

    def get_auth_obj(self,url):

        min_rate_limit_reset = math.inf

        while True:
            for obj in self.auth_objs:
                if obj['rate_limit_reset'][url] < min_rate_limit_reset:
                    min_rate_limit_reset = obj['rate_limit_reset'][url]
                if obj['rate_limit_remaining'][url] > 0 or obj['rate_limit_reset'][url] < int(time.time()):
                    return obj

            # If we get here, there were no auth accounts available to serve this endpoint request, so we will sleep until the next closest reset time
            wait_time = (min_rate_limit_reset - time.time()) + 1
            print("No auth accounts available for this endpoint. Sleeping for {} seconds.".format(wait_time))
            time.sleep(wait_time)

    def make_request(self,url,params,headers=None):
        retries = 0
        max_retries = 5
        self.url_counter['url'] += 1
        auth_obj = self.get_auth_obj(url)

        while True:
            auth = None
            if 'token' in auth_obj:
                headers = {'Authorization': 'Bearer {}'.format(auth_obj['token'])}
            else:
                auth = OAuth1(auth_obj['consumer_key'], auth_obj['consumer_secret'], auth_obj['access_token'], auth_obj['access_token_secret'])

            r = requests.get(url,params=params,headers=headers,auth=auth)
            status_code = r.status_code
            response_headers = r.headers
            try:
                rate_limit_remaining = int(response_headers['x-rate-limit-remaining'])
                rate_limit_reset = int(response_headers['x-rate-limit-reset'])
                auth_obj['rate_limit_remaining'][url] = rate_limit_remaining
                auth_obj['rate_limit_reset'][url] = rate_limit_reset
                #print("Remaining rate-limit: {}".format(response_headers['x-rate-limit-remaining']))
            except:
                pass
            if status_code == 200:
                return r.json()
            elif status_code == 429:
                auth_obj = self.get_auth_obj(url)
                retries += 1
            elif status_code == 401:
                return None
            elif status_code == 404:
                return None
            else:
                print ("Received status error code: {}".format(status_code))
                retries += 1
                time.sleep(retries**2)
            if retries > max_retries:
                return False

    def statuses_lookup(self,tweet_ids):
        params = {}
        params['tweet_mode'] = "extended"
        params['trim_user'] = False
        params['include_entities'] = True
        params['id'] = ','.join([str(x) for x in tweet_ids])
        api_endpoint = "{}{}".format(self.base_url,"1.1/statuses/lookup.json")
        tweets = self.make_request(api_endpoint,params=params)
        return tweets


api = Api()

# Load list of ids from file
fh = open("tweet_ids.csv","r")
ids = [int(x) for x in fh.read().split("\n") if x is not '']
fh.close()

# Sort the ids ascending
ids.sort()

# Open file for writing tweet data
fh = open("trump_tweets.ndjson","w")

while ids:
    # Batch requests so that each request sends a max of 100 ids
    batch = [x for x in ids[:100] if x is not '']
    print ("Fetching batch of {} tweets...".format(len(batch)))

    # Call the API
    tweets = api.statuses_lookup(batch)

    # Sort the returned tweets by their id ascending
    tweets = sorted(tweets, key=lambda k: int(k['id']))

    # Process tweets and write them to file
    for tweet in tweets:
        user = tweet['user']['screen_name'].lower()
        if user != 'realdonaldtrump': # Make sure the tweet is actually from the correct account
            continue
        json_dump = json.dumps(tweet,escape_forward_slashes=False,sort_keys=True,ensure_ascii=True)
        fh.write(json_dump+"\n")

    # Delete previous batch
    del ids[:100]
