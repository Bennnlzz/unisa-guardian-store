import requests
from requests.exceptions import SSLError, RequestException

def check_redirect_vulnerability(base_url, target_redirect_url, secondary_redirect_url):
    try:
        test_url = f"{base_url}?to={target_redirect_url}?to={secondary_redirect_url}"


        response = requests.get(test_url, allow_redirects=True, verify=False)


        if response.status_code == 406:
            print(f"[SAFE] {test_url} was rejected (406), indicating a safe state.")
        elif response.status_code == 200:
            final_url = response.url
            print(f"[INFO] {test_url} redirected to: {final_url}")
            if final_url == target_redirect_url:
                print(f"[VULNERABLE] {test_url} redirects to a malicious site: {final_url}")
            elif final_url == secondary_redirect_url:
                print(f"[SAFE] {test_url} redirects as expected, final URL is {final_url}")
            else:
                print(f"[VULNERABLE] {test_url} redirects to an unexpected site: {final_url}")
        else:
            print(f"[INFO] {test_url} returned status code: {response.status_code}")

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
