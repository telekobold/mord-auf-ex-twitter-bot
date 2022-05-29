#!/usr/bin/python

import typing
import tweepy
import urllib.request as urlreq
import hashlib
import time
from datetime import datetime
import re

import credentials # ignored via .gitignore

URL: str = "https://mordaufex.podigee.io/"


"""
def create_api_client_v1_1():
"""
#    :returns: A new tweepy Twitter API v1 Client using the imported credentials.
"""
    auth = tweepy.OAuthHandler(credentials.consumer_key, credentials.consumer_secret)
    auth.set_access_token(credentials.access_token, credentials.access_token_secret)
    api = tweepy.API(auth, wait_on_rate_limit=True)
    api.verify_credentials()
    
    return api
"""


def create_api_client_v2() -> tweepy.client.Client:
    """
    :returns: A new tweepy Twitter API v2 Client using the imported credentials.
    """
    return tweepy.Client(bearer_token = credentials.bearer_token,
                         consumer_key = credentials.consumer_key,
                         consumer_secret = credentials.consumer_secret,
                         access_token = credentials.access_token,
                         access_token_secret = credentials.access_token_secret)


def current_date_str() -> str:
    """
    :returns: the current date in the form "yyyy-mm-dd;hh:mm:ss"
    """
    return datetime.now().strftime("%Y-%m-%d;%H:%M:%S")


def website_content_and_hash(url_string: str) -> typing.Tuple[str, str]:
    """
    :url_string: A URL to a HTML page (or to a webserver generating such a page).
    :returns:    A tuple of the page's HTML source and the SHA256 hash of this
                 HTML source.
                 The returned hash value is not exactly the hash value of the
                 returned content since the returned content is a utf-8
                 encoding of the content form which the hash value was
                 generated.
    """
    user_agent_string_win10_firefox: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0"
    request = urlreq.Request(url_string, headers={"User Agent": user_agent_string_win10_firefox})
    website_content_bytes: bytes = urlreq.urlopen(request).read()
    website_content: str = website_content_bytes.decode("utf-8")
    website_content_hash: str = hashlib.sha256(website_content_bytes).hexdigest()
    
    return website_content, website_content_hash


def get_newest_podcast_direct_link(site_source: str) -> str:
    """
    :site_source: A string containing well-formed HTML code.
    :returns:     The direct link to the newest podcast 
                  or `None` if no h1 element matching the topmost podcast 
                  post h1 pattern could be found.
    """
    # TODO: Rewrite this so that `direct_link_regex` can be used in the 
    # definition of `newest_post_h1_regex` somehow (to avoid code duplication).
    newest_post_h1_regex: re.Pattern = re.compile(r"<h1 class=\"post-heading\">\n {0,20}<a href=\"/[0-9]{1,3}-[a-zA-Z0-9äöüÄÖÜß\-]*\">#[0-9]{1,3}[a-zA-Z0-9äöüÄÖÜß ?!:;,.]*</a>\n {0,20}</h1>")
    # The first match should be the newest podcast post:
    substring_match: re.Match = newest_post_h1_regex.search(site_source)
    if substring_match:
        newest_podcast_h1: str = site_source[substring_match.start():substring_match.end()]
        # Extract the direct link to the new podcast:
        direct_link_regex: re.Pattern = re.compile(r"<a href=\"/[0-9]{1,3}-[a-zA-Z0-9äöüÄÖÜß\-]*\">#[0-9]{1,3}[a-zA-Z0-9äöüÄÖÜß ?!:;,.]*</a>")
        direct_link_match: re.Match = direct_link_regex.search(newest_podcast_h1)
        return newest_podcast_h1[direct_link_match.start(): direct_link_match.end()]
    else:
        return None


def tweet_new_podcast() -> None:
    """
    Checks if a new podcast has been published on `URL`. If so, 
    posts a new tweet.
    """
    error_string: str = f"{current_date_str()}: The schema of {URL} seems to have changed!"
    last_content, last_hash = website_content_and_hash(URL)
    last_link: str = get_newest_podcast_direct_link(last_content)
    print(f"type(last_link) = {type(last_link)}")
    print(f"last_link = {last_link}")
    if not last_link:
        print(error_string)
        return
    while(True):
        print("Entered loop")
        # TODO: Test with 5 (5 seconds) and comment out the tweet functionality
        # for that:
        time.sleep(5) # Repeat the check every half hour # 1800
        current_content, current_hash = website_content_and_hash(URL)
        print(f"type(current_hash) = {type(current_hash)}")
        print(f"current_hash = {current_hash}")
        print(f"type(last_hash) = {type(last_hash)}")
        print(f"last_hash = {last_hash}")
        # BUG: This is False every time the loop enters:
        # Reason: The hash value is different every time - TODO: fix that
        if current_hash == last_hash:
            print(f"{current_date_str()}: No update!")
            continue
        current_link: str = get_newest_podcast_direct_link(current_content)
        print(f"type(current_link) = {type(current_link)}")
        print(f"current_link = {current_link}")
        if not current_link:
            print(error_string)
            return
        if last_link != current_link:
            print(f"{current_date_str()}: Obviously, something other than a new post was changed on {URL}!")
            continue
        else:
            print(f"{current_date_str()}: Now posting new tweet!")
            #api_client.update_status(f"Ein neuer Mord auf Ex-Podcast wurde veröffentlicht: {current_link}") # Twitter API, Version 1
            # BUG: The link must be nicely formatted!
            #api_client.create_tweet(text=f"Ein neuer Mord auf Ex-Podcast wurde veröffentlicht: {current_link}")
            last_hash = current_hash
            last_link = current_link


if __name__ == "__main__":
    print("Started the @mordaufex Twitter bot!")
    api_client = create_api_client_v2()
    tweet_new_podcast()