import requests
import json
import ast

def xss_test(**url_params):
    file = input("Enter the xss payloads containing file to test: ")
    uri = input("Enter the uri to test: ")
    uri_parameters = input("Enter the uri parameter to test: ")
    req_headers = ast.literal_eval(input("Enter the headers to be sent with the request: "))
    http_method = input("Enter the HTTP method: ").upper().strip()
    http_req_type = input("Enter the request type: ").upper().strip()
    fl = open(file, 'r+')
    vulnerable_param = []
    for payload in fl:
        for uparam in uri_parameters.split(','):
            if uparam in vulnerable_param:
                continue
            #print(uparam,payload)
            url_params[uparam] = payload.rstrip()
            if http_method == "GET" and http_req_type == "XFORM":
                response = requests.get(uri, params=url_params, headers = req_headers)
            elif http_method == "POST" and http_req_type == "XFORM":
                response = requests.post(uri, data=url_params, headers = req_headers)
            elif http_method == "POST" and http_req_type == "JSON":
                response = requests.post(uri, json=url_params, headers = req_headers)
                #print(response.headers)
                #print(response.content)
                if payload.rstrip() in str(response.content) and 'application/json' not in response.headers['Content-Type']:
                    print('{} Vulnerable to XSS and the payload is {}'.format(uparam, payload.rstrip()))
                    vulnerable_param.append(uparam)
                    url_params[uparam] = "aaaa"
                    continue
                else:
                    print('{} Not Vulnerable to XSS'.format(uparam))
                    url_params[uparam] = "aaaa"
                    continue
            if payload.rstrip() in str(response.content):
                print('{} Vulnerable to XSS and the payload is {}'.format(uparam, payload.rstrip()))
                vulnerable_param.append(uparam)
                url_params[uparam] = "aaaa"
            else:
                print('{} Not Vulnerable to XSS'.format(uparam))
                url_params[uparam] = "aaaa"
    print("Test complete")
    fl.close()


a = xss_test(a="test",b=123)
print(a)

