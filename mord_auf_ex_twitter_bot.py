#!/usr/bin/python

"""
"THE BEER-WARE LICENSE" (Revision 42):
Michael Merz <www.telekobold.de> wrote this file. As long as you retain this 
notice you can do whatever you want with this stuff. If we meet some day, and 
you think this stuff is worth it, you can buy me a beer in return. telekobold.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
SOFTWARE.
"""

import typing
import logging
import enum
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


class DateType(enum.Enum):
    FILENAME = "FILENAME"
    STRING = "STRING"


def current_date_str(datetype: DateType) -> str:
    """
    :datetype: used to indicate for which application the returned string
               should be used.
    :returns:  the current date in the form "yyyy-mm-dd;hh:mm:ss"
    """
    return datetime.now().strftime("%Y-%m-%d_%H_%M_%S" if datetype == DateType.FILENAME else "%Y-%m-%d, %H:%M:%S")


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
            #print(line)
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


def get_newest_podcast_number_and_direct_link(site_source: str) -> typing.Tuple[str, str]:
    """
    :site_source: A string containing well-formed HTML code.
    :returns:     A tuple containing the number of and the direct link to
                  the newest podcast or `None` if no h1 element matching 
                  the topmost podcast post h1 pattern could be found.
    """
    # TODO: Rewrite this so that `direct_link_regex` can be used in the 
    # definition of `newest_post_h1_regex` somehow (to avoid code duplication).
    newest_post_h1_regex: re.Pattern = re.compile(r"<h1 class=\"post-heading\">\n {0,20}<a href=\"/[0-9]{1,3}-[a-zA-Z0-9??????????????\-]*\">#[0-9]{1,3}[a-zA-Z0-9?????????????? ?!:;,.]*</a>\n {0,20}</h1>")
    # The first match should be the newest podcast post:
    substring_match: re.Match = newest_post_h1_regex.search(site_source)
    if substring_match:
        newest_podcast_h1: str = site_source[substring_match.start():substring_match.end()]
        # Extract the number of the new podcast:
        number_find_regex: re.Pattern = re.compile(r">#[0-9]{1,3}")
        number_find_match: re.Match = number_find_regex.search(newest_podcast_h1)
        number: str = newest_podcast_h1[number_find_match.start()+2:number_find_match.end()]
        #print(f"number = {number}")
        # Extract the direct link to the new podcast:
        direct_link_regex: re.Pattern = re.compile(r"<a href=\"/[0-9]{1,3}-[a-zA-Z0-9??????????????\-]*\">")
        direct_link_match: re.Match = direct_link_regex.search(newest_podcast_h1)
        relative_link: str = newest_podcast_h1[direct_link_match.start(): direct_link_match.end()]
        absolute_link: str = URL + relative_link[10:len(relative_link)-2]
        return number, absolute_link
    else:
        return None


def tweet_new_podcast() -> None:
    """
    Checks if a new podcast has been published on `URL`. If so, 
    posts a new tweet.
    """
    error_string: str = f"{current_date_str(DateType.STRING)}: The schema of {URL} seems to have changed!"
    
    last_content, last_hash = get_filtered_website_content_and_hash()
    last_number, last_link = get_newest_podcast_number_and_direct_link(last_content)
    #print(f"last_link = {last_link}")
    if not last_link:
        logging.warning(f"{current_date_str(DateType.STRING)}: {error_string}")
        return
    while(True):
        #print("Entered loop")
        # TODO: Test with 5 (5 seconds) and comment out the tweet functionality
        # for that:
        time.sleep(1800) # Repeat the check every half hour
        current_content, current_hash = get_filtered_website_content_and_hash()
        #print(f"current_hash = {current_hash}")
        #print(f"last_hash = {last_hash}")
        if current_hash == last_hash:
            logging.info(f"{current_date_str(DateType.STRING)}: No update")
            continue
        current_number, current_link = get_newest_podcast_number_and_direct_link(current_content)
        #print(f"current_link = {current_link}")
        if not current_link:
            logging.error(f"{current_date_str(DateType.STRING)}: {error_string}")
            return
        if last_link != current_link:
            logging.warning(f"{current_date_str(DateType.STRING)}: Obviously, something other than a new post was changed on {URL}!")
            continue
        else:
            logging.info(f"{current_date_str(DateType.STRING)}: Now posting a new tweet.")
            publish_message = f"Mord auf Ex-Podcast Nummer {current_number} wurde ver??ffentlicht: {current_link}"
            api_client.create_tweet(text=publish_message)
            #print(publish_message)
            logging.info(f"{current_date_str(DateType.STRING)}: Posted a new tweet: {publish_message}")
            last_hash = current_hash
            last_link = current_link


if __name__ == "__main__":
    # The parameter `encoding="utf-8"` is only supported in Python versions >= 3.9:
    logging.basicConfig(filename=f"mordaufex_log_{current_date_str(DateType.FILENAME)}.log", level=logging.INFO)
    logging.info(f"{current_date_str(DateType.STRING)}: Started the @mordaufex Twitter bot.")
    api_client = create_api_client_v2()
    tweet_new_podcast()
