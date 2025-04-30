import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from utils import get_logger
import pickle
import os

logger = get_logger("CRAWLER")

visited_urls = set()
unique_urls = set()
subdomain_counts = {}

# load needed data from disk, otherwise create the structure
if os.path.exists("visited_urls.pkl"):
    with open("visited_urls.pkl", "rb") as f:
        visited_urls = pickle.load(f)
else:
    visited_urls = set()

if os.path.exists("unique_urls.pkl"):
    with open("unique_urls.pkl", "rb") as f:
        unique_urls = pickle.load(f)
else: 
    unique_urls = set()

if os.path.exists("subdomain_counts.pkl"):
    with open("subdomain_counts.pkl", "rb") as f:
        subdomain_counts = pickle.load(f)
else:
    subdomain_counts = {}


def scraper(url, resp):
    links = extract_next_links(url, resp)
    
    # dumping data onto disk
    with open("visited_urls.pkl", "wb") as f:
        pickle.dump(visited_urls, f)

    with open("unique_urls.pkl", "wb") as f:
        pickle.dump(unique_urls, f)

    with open("subdomain_counts.pkl", "wb") as f:
        pickle.dump(subdomain_counts, f)
    
    return [link for link in links]


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content]
    output_links = []
    parsed = urlparse(url)

    redirect_codes = [301, 302, 303, 307, 308]
    if resp.status in redirect_codes:
        logger.warning(f"Redirect detected at {url}")

    if resp is None or resp.status != 200 or resp.raw_response is None:
        logger.info(f"{url} did not return a 200 status")
        return output_links
    else:
        unique_urls.add(url)
        subdomain = parsed.netloc.lower()
        if subdomain in subdomain_counts:
            subdomain_counts[subdomain] += 1
            logger.info(f"{subdomain}: has {subdomain_counts[subdomain]} unique pages")
        logger.info(f"# of unique sites visited: {len(unique_urls)}")
        
    
    soup = BeautifulSoup(resp.raw_response.content, "html.parser")

    text = soup.get_text()
    words = text.split()

    if len(words) < 100:
        return output_links
    
    for link_tag in soup.find_all('a'):
        href = link_tag.get('href')
        if href:
            absolute_url = urljoin(url, href)
            clean_url, fragment = urldefrag(absolute_url)
            subdomain = parsed.netloc.lower()

            if clean_url not in visited_urls:
                if is_valid(clean_url):
                    visited_urls.add(clean_url)
                    output_links.append(clean_url)
                    if subdomain not in subdomain_counts:
                        subdomain_counts[subdomain] = 0
                # add to visited urls to avoid checking if it is valid again
                else:
                    visited_urls.add(clean_url)
    return output_links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    allowed_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]
    unallowed_queries = ["share=", "ical=", "outlook-ical=", "eventDate=", "tribe-bar-date=", "eventDisplay=", 
        "action=download", "action=login", "action=upload", "action=edit", "action=diff", "redirect_to=",
        "from="]
    calendar_keywords = ["calendar", "events", "schedule", "month"]

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if parsed.scheme not in set(["http", "https"]):
            return False

        if re.search(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz"
            + r"|img|h|cp|mol|db|py|cpp|ipynb|ppsx|can|war|apk)$", parsed.path.lower()):
            return False
        

        # both swiki and wiki subdomains treated as invalid since it states on site "Access to most of the 
        # information in these ICS Wiki pages are restricted to ICS affiliates. Please make sure to login 
        # using an ICS username/password."
        if domain == "swiki.ics.uci.edu":
            return False

        if domain == "wiki.ics.uci.edu":
            return False

        # found main information before look at pages, useless to go through each page
        if domain == "ngs.ics.uci.edu" and ("/page/" in parsed.path.lower() or 
            "/tag/" in parsed.path.lower()):
            return False

        # found in robots.txt of many sites, leads to a WordPress login so no information
        if parsed.path.startswith("/wp-admin/"):
            return False

        # blocking queries that lead to no information, is a trap, or leads to an error response
        for invalid_query in unallowed_queries:
            if invalid_query in parsed.query:
                logger.info(f"{url} has a bad query: {invalid_query}")
                return False

        # checks for date patterns such as 2022-04-01 or 2022/04/01 to avoid calendar traps
        if any(part in calendar_keywords for part in re.split(r"[/]", parsed.path.lower())):
            if date_pattern(parsed.path):
                logger.info(f"{url} is a calendar trap")
                return False

        # robots.txt check for domains & subdomains found
        # if robots_txt_check(url, parsed) == False:
            # return False
        
        
        # special case for today.uci.edu since a path is specified
        if domain == "today.uci.edu":
            if parsed.path.startswith("/department/information_computer_sciences"):
                return True
            else:
                return False
        
        # otherwise test if domain is apart of the allowed list
        for allowed in allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        return False
        
    except TypeError:
        logger.error(f"TypeError for {parsed}")
        raise

def date_pattern(path):
    parts = re.split(r"[/-]", path)

    numbers = [p for p in parts if p.isdigit()]

    if len(numbers) >= 2:
        has_year = any(len(num) == 4 and 1900 <= int(num) <= 2100 for num in numbers)
        return has_year
    
    return False

def robots_txt_check(url, parsed):
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    if domain == "ics.uci.edu" and (path.startswith("/people") or 
        parsed.path.startswith("/happening")):
        logger.info(f"{url} is blocked by robots.txt")
        return False

    if domain == "informatics.uci.edu" and path.startswith("/research/"):
        logger.info(f"{url} is blocked by robots.txt")
        return False
        
    if domain == "cs.uci.edu" and (path.startswith("/people") or 
        path.startswith("/happening")):
        logger.info(f"{url} is blocked by robots.txt")
        return False
    
    if domain == "cs.ics.uci.edu" and (path.startswith("/people") or 
        path.startswith("/happening")):
        logger.info(f"{url} is blocked by robots.txt")
        return False

    if domain == "-db.ics.uci.edu" and (path.startswith("/cgi-bin/") or
        path.startswith("/web-images/") or path.startswith("/downloads/") or 
        path.startswith("/glimpse_index/") or path.startswith("/pages/internal")):
        logger.info(f"{url} is blocked by robots.txt")
        return False

    if domain == "statistics-stage.ics.uci.edu" and (path.startswith("/people") or 
        path.startswith("/happening")):
        logger.info(f"{url} is blocked by robots.txt")
        return False

    return True

    
if __name__ == "__main__":
    with open("subdomains.txt2", "w") as f:
        for subdomain, count in sorted(subdomain_counts.items(), key=lambda item: item[1], reverse=True):
            count = subdomain_counts[subdomain]
            f.write(f"{subdomain}, {count}\n")

