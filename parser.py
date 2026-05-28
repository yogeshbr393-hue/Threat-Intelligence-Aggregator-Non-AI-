import requests
from validator import is_valid_ioc


def fetch_url_feed(url):

    results = []

    try:

        response = requests.get(url, timeout=10)

        lines = response.text.splitlines()

        for line in lines:

            line = line.strip()

            if (
                line
                and not line.startswith("#")
                and is_valid_ioc(line)
            ):

                results.append({
                    "type": "ioc",
                    "value": line,
                    "source": url
                })

    except Exception as e:

        print("Error:", e)

    return results
