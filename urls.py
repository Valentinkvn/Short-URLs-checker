import re
import sys
import requests
import time
import concurrent.futures
import json
from urllib.parse import urlparse
import email
from email import policy
from email.parser import BytesParser
from pydnsbl import DNSBLDomainChecker, providers
from pydnsbl.providers import Provider


def main(input_type, file_name):
    start = time.perf_counter()

    if input_type == "0":
        if ".txt" in file_name:
            urls = urls_from_file(file_name)
        else:
            print("Error: Choose a .txt file.")
            exit(0)
    elif input_type == "1":
        if ".eml" in file_name:
            mail_body = get_mail_body(file_name)
            urls = get_urls_from_mail(mail_body)
        else:
            print("Error: Choose a .eml file.")
            exit(0)

    # list to store the returned found urls
    long_urls = []

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = executor.map(find_expanded_url, urls)
        for i, result in enumerate(results):
            # check if a valid link is found
            if "http" in result:
                long_urls.append(result)
            print(str(i+1) + ". " + urls[i] + "\n\t -> " + result)

    google_safe_browsing(long_urls)

    uribl_safe_browsing(long_urls)

    finish = time.perf_counter()
    print(f"Finished in {round(finish-start, 2)} second(s)")


# Function that finds the expanded URLs from short URLs.
# This function uses the http://checkshorturl.com/ service to find the URLs.
# A POST request is created having the short URL information and this function
# will retrieve the long url from the returned info of the POST request.
# To find the URL from the returned info, two regular expressions are used:
# one to find the url block (a <td> html tag) and one to find the URL itself.
def find_expanded_url(url_to_search):
    service_url = "http://checkshorturl.com/expand.php"
    payload = {'u': url_to_search}
    page = requests.post(service_url, data=payload)

    tag_pattern = re.compile(r"<\s*td[^>]*>((.|\n)*?)<\s*/\s*td>")

    tag_matches = tag_pattern.finditer(page.text)

    # match the second td tag because it has the long link in it
    tag_match = next((x for i, x in enumerate(tag_matches) if i == 1), None)

    if tag_match is None:
        return "Error: No link found!"
    else:

        # this is a more complex regular expression for URLs
        # one simplier re should be 'https?://(www\.)?(\w+)(\.\w+)'m
        # but it takes into consideration just the domain name
        url_pattern = re.compile(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

        url_matches = url_pattern.finditer(tag_match[0])

        # match the second link because it is the text of the <td> tag
        url_match = next(x for i, x in enumerate(url_matches) if i == 1)

        return url_match[0]


# Function that uses the Google Safe Browsing API to find the listing info
# about a domain. This function takes as input a list of expanded URLs and
# prints the listing status of the domains inside the URLs.
def google_safe_browsing(long_urls):
    print("--------------------------------------------------------------")
    api_key = 'xxx'
    url = ("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
        api_key)
    payload_json = {
      "client": {
        "clientId":      "valentinpatrascu",
        "clientVersion": "1.0"
      },
      "threatInfo": {
        "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        "platformTypes":    ["LINUX", "WINDOWS", "ANDROID", "IOS"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [
        ]
      }
    }

    # append the input URLs list into the json of the needed POST request
    for urls in long_urls:
        payload_json["threatInfo"]["threatEntries"].append({"url": urls})

    page = requests.post(url, json=payload_json)
    json_obj = page.json()
    if len(json_obj) != 0:
        for match in json_obj["matches"]:
            print("Threat type: " + match["threatType"] +
                " for " + match["platformType"] + " platform: " +
                " found at address: " + match["threat"]["url"])
    else:
        print("Google Safe Browsing found no threat match!")

    print("--------------------------------------------------------------")


# Function that uses the multi.uribl.com domain checker to find the listing
# of the URLs from the long_urls list
def uribl_safe_browsing(long_urls):
    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = executor.map(check_domain, long_urls)
        for i, result in enumerate(results):
            print(str(i+1) + ". " + long_urls[i])
            if result > 0:
                print("\tBlacklisted")
            elif result < 0:
                print("\tError: DNS domain")
            else:
                print("\tNon blacklisted")


# Helper function that takes the URL and checks it against the multi.uribl.com
# service using the DNSBLDomainChecker obj available due to the pydnsbl import
# The returned value will be the blacklisted status
def check_domain(url):
    providers = [Provider('multi.uribl.com')]
    checker = DNSBLDomainChecker(providers=providers)
    try:
        result = checker.check(extract_domain(url))
        return result.blacklisted
    except:
        return -1


# Helper function that extracts the domain from a long URL
def extract_domain(url):
    domain = urlparse(url).netloc
    return domain


# Function that extracts all the short URLs from a text file
def urls_from_file(file):
    try:
        urls_file = open(file, 'r')
    except IOError as error:
        print(error)
        exit(0)
    content = urls_file.read()
    urls_lines = content.split("\n")
    urls_file.close()
    return urls_lines


# Function that opens a .eml file,
# parse it's information and returns the its body
def get_mail_body(file_path):
    try:
        with open(file_path, "rb") as fp:
            msg = BytesParser(policy=policy.default).parse(fp)
    except IOError as error:
        print(error)
        exit(0)
    body = msg.get_body(preferencelist=('plain')).get_content()
    return body


# Function that, using a regular expression,
# finds all the links from a mail body
def get_urls_from_mail(mail_body):
    url_pattern = re.compile(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

    url_matches = url_pattern.finditer(mail_body)

    urls = []
    # match the second link because it is the text of the <td> tag
    for i, url in enumerate(url_matches):
        urls.append(url[0])

    return urls


# Use the __name__ builtin variable to run the main function with two parameters
# taken from the command line, the first one is the input data type (.txt file
# or .eml file) and the second one the name of the file
if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
