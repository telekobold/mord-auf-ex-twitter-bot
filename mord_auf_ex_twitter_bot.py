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


def csrf_token_filter(website_content: bytes) -> str:
    """
    The website `https://mordaufex.podigee.io/` generates a "csrf-token" head 
    tag whose content is different on each call. Of course, this also leads to
    that a different hash value is calculated for each website call.
    
    This function filters the csrf token tag from the website content.
    
    :website_content: the website content (as `bytes` since the urllib function
                      returns the content in this form).
    :returns: the filtered website content as utf-8 string.
    """
    website_content_str = website_content.decode("utf-8")
    website_content_lines = website_content_str.split("\n")
    csrf_token_def_prefix = "<meta name=\"csrf-token\" content=\""
    for line in website_content_lines:
        if csrf_token_def_prefix in line:
            print(line)
            website_content_lines.remove(line)
    
    return "\n".join(website_content_lines)


def get_website_content(url_string: str) -> bytes:
    """
    :url_string: A URL to a HTML page (or to a webserver generating such a page).
    :returns:    The retrieved HTML content.
    """
    user_agent_string_win10_firefox: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0"
    
    request = urlreq.Request(url_string, headers={"User Agent": user_agent_string_win10_firefox})
    
    return urlreq.urlopen(request).read()


def get_hash(content: bytes) -> str:
    """
    :content: an arbitrary string
    :returns: the SHA256 hash value to `content`
    """
    return hashlib.sha256(content).hexdigest()


def get_filtered_website_content_and_hash() -> typing.Tuple[str, str]:
    """
    """
    website_content_bytes: bytes = get_website_content(URL)
    website_content_str_filtered: str = csrf_token_filter(website_content_bytes)
    website_content_bytes_filtered: bytes = website_content_str_filtered.encode("utf-8")
    website_content_hash: str = get_hash(website_content_bytes_filtered)
    
    return website_content_str_filtered, website_content_hash


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
        direct_link_regex: re.Pattern = re.compile(r"<a href=\"/[0-9]{1,3}-[a-zA-Z0-9äöüÄÖÜß\-]*\">")
        direct_link_match: re.Match = direct_link_regex.search(newest_podcast_h1)
        relative_link: str = newest_podcast_h1[direct_link_match.start(): direct_link_match.end()]
        absolute_link: str = URL + relative_link[10:len(relative_link)-2]
        return absolute_link
    else:
        return None


def tweet_new_podcast() -> None:
    """
    Checks if a new podcast has been published on `URL`. If so, 
    posts a new tweet.
    """
    error_string: str = f"{current_date_str()}: The schema of {URL} seems to have changed!"
    
    last_content, last_hash = get_filtered_website_content_and_hash()
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
        current_content, current_hash = get_filtered_website_content_and_hash()
        print(f"type(current_hash) = {type(current_hash)}")
        print(f"current_hash = {current_hash}")
        print(f"type(last_hash) = {type(last_hash)}")
        print(f"last_hash = {last_hash}")
        """
        if current_hash == last_hash:
            print(f"{current_date_str()}: No update!")
            continue
        """
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
            #api_client.create_tweet(text=f"Ein neuer Mord auf Ex-Podcast wurde veröffentlicht: {current_link}")
            print(f"Ein neuer Mord auf Ex-Podcast wurde veröffentlicht: {current_link}")
            last_hash = current_hash
            last_link = current_link
            break # For testing purposes - TODO: remove


if __name__ == "__main__":
    print("Started the @mordaufex Twitter bot!")
    api_client = create_api_client_v2()
    tweet_new_podcast()
