import requests
import ast

def xss_test(**url_params):
    file = input("Enter the xss payloads containing file to test: ")
    uri = input("Enter the uri to test: ")
    uri_parameters = input("Enter the uri parameter to test: ")
    req_headers = ast.literal_eval(input("Enter the headers to be sent with the request: "))
    http_method = input("Enter the HTTP method: ").upper()
    fl = open(file, 'r+')
    for payload in fl:
        url_params[uri_parameters] = payload.rstrip()
        if http_method == "GET":
            response = requests.get(uri, params=url_params, headers = req_headers)
        elif http_method == "POST":
            response = requests.post(uri, data=url_params, headers = req_headers)
        if payload.rstrip() in str(response.content):
            print('Vulnerable to XSS: {} uri parameter is effected and the payload is {}'.format(uri_parameters, payload.rstrip()))
            break
        else:
            print('Not Vulnerable to XSS')
    print("Test complete")


a = xss_test(txtSearch="123",a="test")
print(a)
