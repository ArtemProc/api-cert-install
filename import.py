#!/usr/bin/python
'''
.notes
    Filename: api-cert-import.py
    Script version: 1.0.0
 
.prerequisites
    Python 3
    requests
    urllib3
 
.overview
 
    Script is to provide an example how to import SSL Certificate for Prism Element and Prism Central automatically.
    User you are going to use is supposed to have Cluster Admin Role mapping in Prism.
    Script will use REST API V1 Endpoint to submit certificate related data.
    After certificate successfully imported Cluster will restart Prism UI services to apply new certificates. 
 
.disclaimer
    This code is intended as a standalone example. This can be downloaded, 
    copied and/or modified in any way you see fit.
 
    Please be aware that all public code samples provided by Artem are unofficial in nature, are provided as examples only, 
    are unsupported and will need to be heavily scrutinized and potentially modified before they can be used in a production environment. All such code samples are provided on an as-is basis, and Artem expressly disclaims all warranties, express or implied.
  
    All code samples are provided as-is under the MIT license. (https://opensource.org/licenses/MIT)

'''
import sys
import os
import getopt
import urllib3.request
import binascii
import getpass
import requests
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
disable_warnings(InsecureRequestWarning)

def encode_multipart_formdata(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')
    body = (
        "".join("--%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"; filename=\"anything\"\r\n"
                "Content-Type: application/octet-stream""\r\n"
                "\r\n"
                "%s\r\n" % (boundary, field, value)
                for field, value in fields.items()) +
        "--%s--\r\n" % boundary
    )
    content_type = "multipart/form-data; boundary=%s" % boundary
    return body, content_type

def make_request(ip_address,user,payload):

    header = {"content-type": payload[1]}
    auth = HTTPBasicAuth(user, getpass.getpass('Enter the password: '))
    url_list = 'https://{0}:9440/PrismGateway/services/rest/v1/keys/pem/import'.format(ip_address)
    res_list = requests.post(url=url_list, data=payload[0], auth=auth, headers=header, verify=False)
    return res_list

def usage():
    print('To import certificate please use following format')
    print('import.py -k <private-key> -t <key-type> -p <public-cert> -c <ca-chain> -i <prism-ip-or-fqdn> -u <username-with-cluster-admin-mapping>')
    print('Type format names are:\nRSA_2048\nECDSA_256\nECDSA_384\nECDSA_521')

def main(argv):

    private_key = ''
    public_cert = ''
    ca_chain = ''
    key_type = ''
    prism_ip = ''
    user = ''

    try:
        opts, args = getopt.getopt(argv,
        "k:t:p:c:i:u:",
        ["private-key=","key-type=","public-cert=","ca-chain=","ip=","user="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    
    if not opts or len(argv) < 12:
        usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ('-k', '--private-key'):
            print(arg)
            private_key = open(arg,"r").read()            
        elif opt in ('-p', '--public-cert'):
            print(arg)
            public_cert = open(arg,"r").read()            
        elif opt in ('-c', '--ca-chain'):
            print(arg)
            ca_chain = open(arg,"r").read()
        elif opt in ('-t', '--key-type'):
            print(arg)
            key_type = arg
        elif opt in ('-i', '--ip'):
            print(arg)
            prism_ip = arg
        elif opt in ('-u', '--user'):
            print(arg)
            user = arg
            
    request_payload = encode_multipart_formdata({"keyType": key_type,"key": private_key, "cert": public_cert, "caChain": ca_chain})
    print(request_payload[0])

    print(make_request(prism_ip,user,request_payload))

if __name__ == "__main__":
   main(sys.argv[1:])