import requests
from requests.exceptions import SSLError, RequestException
from urllib.parse import urlparse

def check_redirect_vulnerability(base_url, target_redirect_url, secondary_redirect_url):
    try:
        test_url = f"{base_url}?to={target_redirect_url}?to={secondary_redirect_url}"
        response = requests.head(test_url, allow_redirects=True, verify=False)


        final_url_domain = urlparse(response.url).netloc
        target_domain = urlparse(target_redirect_url).netloc


        if final_url_domain == target_domain:
            print(f"[VULNERABLE] {test_url} redirects fully to {target_redirect_url}")
        elif response.url == secondary_redirect_url:
            print(f"[SAFE] {test_url} redirects as expected, final URL is {secondary_redirect_url}")
        else:
            print(f"[SAFE] {test_url} does not redirect to malicious site, final URL is {response.url}")

    except SSLError as ssl_error:
        print(f"SSL error while checking {base_url}: {ssl_error}")
    except RequestException as req_error:
        print(f"Request error occurred while checking {base_url}: {req_error}")

def batch_check_redirect(url_list, target_redirect_url, secondary_redirect_url):
    for url in url_list:
        check_redirect_vulnerability(url, target_redirect_url, secondary_redirect_url)

url_list = [
    "http://127.0.0.1:3000/redirect",
]
target_redirect_url = "https://baidu.com"
secondary_redirect_url = "https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6"

batch_check_redirect(url_list, target_redirect_url, secondary_redirect_url)
