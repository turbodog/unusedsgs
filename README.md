# unusedsgs - Find unused AWS Security Groups with Prisma Cloud

To use, create a ```config.py``` file with your API endpoint and access keys and then run ```python3 unusedsgs.py```
```
CONFIG = {
        'url':        'https://api.prismacloud.io',
        'access_key': '1234',
        'secret_key': 'abcd'
}

DEBUG_MODE = False

# Write RQL output to disk
LOG_JSON = False

CLOUD_ACCOUNT = "my cloud account"

# Usage lookback in hours
LOOKBACK = 24*30
```
