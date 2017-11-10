import requests

def xss_test(**url_params):
    file = input("Enter the xss payloads containing file to test: ")
    uri = input("Enter the uri to test: ")
    uri_parameters = input("Enter the uri parameter to test: ")
    fl = open(file, 'r+')
    for payload in fl:
        url_params[uri_parameters] = payload.rstrip()
        response= requests.get(uri, params=url_params)
        if payload.rstrip() in str(response.content):
            print('Vulnerable to XSS')
            print('{} uri parameter is effected and the payload is {}'.format(uri_parameters, payload.rstrip()))
            break
        else:
            print('Not Vulnerable to XSS')
    print("Test complete")


#result = xss_test(vikram=160988, txtSearch='name', nack='t', id=190829301238, token='abl89430jaca90')
#print(result)
