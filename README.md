# CriminalIPLib
---
Simple Python wrapper around the [CriminalIP](https://www.criminalip.io) API

## Sample usage

``` python
import criminalip

API_KEY = <ADD YOUR UNIQUE KEY HERE>

crimip = criminalip.CriminalIP(API_KEY)
print(crimip.banner_search("ssh"))
```


