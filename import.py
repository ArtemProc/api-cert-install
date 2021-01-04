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
  
<<<<<<< HEAD
    All code samples are © Nutanix, Inc., and are provided as-is under the MIT license. (https://opensource.org/licenses/MIT)
=======
    All code samples are provided as-is under the MIT license. (https://opensource.org/licenses/MIT)

>>>>>>> e5d9d41069b639b64d41a04f717bfeb73b9b9c0e
'''
import sys
import os
import getopt
import urllib3.request
import binascii
import getpass
import argparse
import requests
from OpenSSL import crypto
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

def main():

    private_key = ''
    public_cert = ''
    ca_chain = ''
    key_type = ''
    prism_ip = ''
    user = ''
    parser = argparse.ArgumentParser(description='''Script is to provide an example how to import SSL Certificate for Prism Element and Prism Central automatically.''',
    usage='''To import certificate please use following format.\n
    import.py -k <private-key> -t <key-type> -p <public-cert> -c <ca-chain> -i <prism-ip-or-fqdn> -u <username-with-cluster-admin-mapping>\n
    Type format names are:\nRSA_2048\nECDSA_256\nECDSA_384\nECDSA_521'''
    )
    parser.add_argument('-k','--private_key',type=str, help='Path to private key file', required=True)
    parser.add_argument('-p','--public_cert',type=str, help='Path to server certificate file', required=True)
    parser.add_argument('-c','--ca_chain',type=str, help='Path to CA Chain file', required=True)
    parser.add_argument('-t','--key_type',type=str, help='Server key algorithm', required=True)
    parser.add_argument('-i','--ip',type=str, help='Server ip or FQDN', required=True)
    parser.add_argument('-u','--user',type=str, help='User with Cluster Admin Role Mapping', required=True)
    args = parser.parse_args()
    private_key = open(args.private_key, 'r').read()
    public_cert = open(args.public_cert, 'r').read()
    ca_chain = open(args.ca_chain, 'r').read()
    key_type = args.key_type
    prism_ip = args.ip
    user = user

    try:
        store = crypto.X509Store()
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, public_cert)
        ca_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, ca_chain)
        store.add_cert(ca_certificate)
        store_ctx = crypto.X509StoreContext(store, certificate)
        store_ctx.verify_certificate()
    except Exception as e:
        print(e)
        sys.exit(1)


    request_payload = encode_multipart_formdata({"keyType": key_type,"key": private_key, "cert": public_cert, "caChain": ca_chain})
    
    print(make_request(prism_ip,user,request_payload))

if __name__ == "__main__":
   main()