import requests
import ast

def xss_test(**url_params):
    file = input("Enter the xss payloads containing file to test: ")
    uri = input("Enter the uri to test: ")
    uri_parameters = input("Enter the uri parameter to test: ")
    req_headers = ast.literal_eval(input("Enter the headers to be sent with the request: "))
    http_method = input("Enter the HTTP method: ").upper()
    fl = open(file, 'r+')
    vulnerable_param = []
    for payload in fl:
        for uparam in uri_parameters.split(','):
            if uparam in vulnerable_param:
                continue
            #print(uparam,payload)
            url_params[uparam] = payload.rstrip()
            if http_method == "GET":
                response = requests.get(uri, params=url_params, headers = req_headers)
            elif http_method == "POST":
                response = requests.post(uri, data=url_params, headers = req_headers)
            if payload.rstrip() in str(response.content):
                print('Vulnerable to XSS: {} parameter is effected and the payload is {}'.format(uparam, payload.rstrip()))
                vulnerable_param.append(uparam)
                url_params[uparam] = "aaaa"
            else:
                print('{} Not Vulnerable to XSS'.format(uparam))
                url_params[uparam] = "aaaa"
    print("Test complete")


a = xss_test(txtSearch="123",a="test",b=123)
print(a)
