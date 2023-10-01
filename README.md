# pyCriminalIP
---
Simple Python wrapper around the [CriminalIP](https://www.criminalip.io) API

## Sample usage

``` python
from criminalip.client import Client

API_KEY = <ADD YOUR UNIQUE KEY HERE>

crimip = Client(API_KEY)
print(crimip.banner_search("ssh"))
```


