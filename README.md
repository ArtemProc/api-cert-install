# Import SSL Certificate for Prism Element/Prism Central.

## Introduction

This script is example of REST API call way to import SSL Certificate for Prism Element/Prism Central web interface.
Script has verification of Signed certificate to CA file provided.

## Requirements
```
Python 3
requests
urllib3
argparser
pyOpenSSL
```
## How to use

To import certificate please use following format

```import.py -k <private-key> -t <key-type> -p <public-cert> -c <ca-chain> -i <prism-ip-or-fqdn> -u <username-with-cluster-admin-mapping>```

Type format names are:

```
RSA_2048
ECDSA_256
ECDSA_384
ECDSA_521
```

## To DO

Add handler for errors related to auth and replies from API

So far it just shows code status for request.

## License
[MIT](https://choosealicense.com/licenses/mit/)
