import xlrd
import os

def delete_file():
    # Delete files every time at the start having Issue Keys
    if os.path.isfile("sql injection.txt"):
        os.remove("sql injection.txt")
    elif os.path.isfile("xss.txt"):
        os.remove("xss.txt")
    elif os.path.isfile("rce.txt"):
        os.remove("rce.txt")
    elif os.path.isfile("ukvc.txt"):
        os.remove("ukvc.txt")
    elif os.path.isfile("idor.txt"):
        os.remove("idor.txt")
    elif os.path.isfile("broken authentication.txt"):
        os.remove("broken authentication.txt")
    elif os.path.isfile("csrf.txt"):
        os.remove("csrf.txt")
    elif os.path.isfile("xml.txt"):
        os.remove("xml.txt")
    elif os.path.isfile("s3.txt"):
        os.remove("s3.txt")
    elif os.path.isfile("security misconfiguration.txt"):
        os.remove("security misconfiguration.txt")
    elif os.path.isfile("sensitive data exposure.txt"):
        os.remove("sensitive data exposure.txt")
    elif os.path.isfile("open redirection.txt"):
        os.remove("open redirection.txt")
    elif os.path.isfile("other security issue.txt"):
        os.remove("other security issue.txt")
    elif os.path.isfile("missing function level access.txt"):
        os.remove("missing function level access.txt")
    elif os.path.isfile("aws account.txt"):
        os.remove("aws account.txt")
    elif os.path.isfile("click jacking.txt"):
        os.remove("click jacking.txt")
    elif os.path.isfile("dos.txt"):
        os.remove("dos.txt")
    elif os.path.isfile("no category.txt"):
        os.remove("no category.txt")

def classification():
    Delete_file()
    file_location = "test1.xlsx"
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    number_of_rows = sheet.nrows
    number_of_columns = sheet.ncols
    # List to contain Issue Keys
    sqli_key = []
    xss_key = []
    remote_injection_key = []
    idor_key = []
    ukvc_key = []
    broken_authentication_key = []
    csrf_key = []
    xml_key = []
    s3_key = []
    security_misconfiguration_key = []
    sensitive_data_exposure_key = []
    open_redirection_key = []
    other_security_issue_key = []
    missing_functional_level_access_key = []
    aws_account_key = []
    click_jacking_key = []
    dos_key = []
    no_category_key = []
    # Counter to keep track of number of defects with respect to the vulnerabilities category
    no_sqli_issues = 0
    no_xss_issues = 0
    no_remote_injection_issues = 0
    no_idor_issues = 0
    no_ukvc_issues = 0
    no_broken_authentication_issues = 0
    no_csrf_issues = 0
    no_xml_issues = 0
    no_s3_issues = 0
    no_security_misconfiguration_issues = 0
    no_sensitive_data_exposure_issues = 0
    no_open_redirection_issues = 0
    no_other_security_issues = 0
    no_missing_functional_level_access_issues = 0
    no_aws_account_issues = 0
    no_click_jacking_issues = 0
    no_dos_issues = 0
    no_no_category_issues = 0
    # List of keywords to search for vulnerabilities by category
    sql_injection_search = ['sql']
    xss_search = ['xss', 'cross-site scripting', 'cross site scripting', 'reflected', 'stored', 'input validation', 'input handling', 'sanitized']
    remote_injection_search = ['csv', 'remote code execution', 'xauth', 'teemu', '.qbw', 'commands', 'silently']
    idor_search = ['manipulation', 'response', 'traversal', 'lfi', 'local file inclusion', 'business logic flaw', 'pollution', 'inclusion', 'reference', 'insecure direct object reference', 'spoofing', 'authorization', 'authenticate']
    broken_authentication_search = ['password', 'policy', 'session', 'httponly', 'cookie', 'mfa', 'rotate', 'flag', 'authentication', 'rotated', 'recaptcha', 'anti-automation', 'pci-sensitive', 'broken', 'locking', 'lockout', 'bruteforce', 'rate limiting', 'brute force', 'brute-force', 'ticket', 'enumration', 'autocomplete']
    csrf_search = ['csrf', 'cross-site request forgery', 'cross site request forgery']
    xml_search = ['xml', 'xxe', 'xpath']
    s3_search = ['s3', 'bucket']
    security_misconfiguration_search = ['error', 'keytab', 'stack', 'trace', 'path', 'internal', 'listing','default account', 'header','headers', 'class', 'cors', 'suspicious','nginx', 'host header','windows remote', 'relies', 'httpoxy', 'trace', 'track', 'rds', 'management console', 'group', 'jmx', 'ornange', 'subdomain', 'options method', 'cross-origin resource sharing', 'cross origin resource sharing', 'restored', 'ftp', 'sftp', 'apache', 'ssh', 'entries', 'cleanup', 'jboss', 'everyone', 'rouge', 'exploitation', 'take-over', 'take over', 'customer downloads', 'lack of controls', 'sql_read', 'vpc flow', 'sniffing', 'uploads', 'upload', 'inserting', 'cloudtrail', 'unresolved', 'mobile gateway', 'sbgsec-3821', 'listing', 'kaos', 'slow http post', 'crossdomain.xml', 'debug', 'debugger', '62026', 'fingerprinting', 'allaire', 'attachments', 'violation', 'deprecated', 'realm', 'listable', 'banner', 'multiple security', 'predictable resource', 'relay', 'deployment', 'server misconfiguration', 'jenkins', 'rundeck', 'peering', '03/02/2016', 'encrypted', 'robots.txt', 'misconfiguration', 'apple', 'referal', 'detection', 'jailbreak', 'indexing', 'orangehrm', '199.187.158.195', '199.187.158.196', '199.16.142.42', '12.149.173.50', 'abused', 'flood', 'open proxy', 'pos-build']
    sensitive_data_exposure_search = ['cipher','cache', 'sensitive', 'social', 'ssn', 'mask', 'clear', 'plain', 'http', 'ssl', 'rc4', 'swagger', 'tls', 'cachable', 'cacheable', 'strict', 'internal ip', 'wsdl', 'secrets', 'disclosure', 'secret', 'private auth', 'exposed', 'data handling', 'privateAuth+', 'birthday', 'confidential', 'exposure', 'exposing', 'leakage', 'transport', 'encryption', 'oauth', 'null', 'hashing', 'hash', 'certificates', 'unencrypted', 'communication', 'cbc', 'cbc3', 'plain-text', 'credentials', 'credential', 'key', 'keys', 're-keying', 'android:application', 'pinning', 'unmasked', 'cached', 'caching', 'pii', 'transfer']
    open_redirection_search = ['url', 'redirection', 'unvalidated', 'openid', 'redirector', 'redirect']
    missing_functional_level_access_search = ['0-day', 'missing', 'a7', 'bypass', 'non-admin', 'ifsp', 'failure', 'faliure', 'abuse of functionality', 'unattended', 'missing function level access control', 'anonymous', 'auth', 'escalation']
    other_security_issue_search = ['onboard', 'other', 'jira-python', 'blocked', '404 alerts', 'malware', 'aggregation', 'recon check', 'text injection', 'whitelist', 'whitelisting', 'whitelisted', 'regulatory', 'mightybell', 'fundbox', 'logs', 'vyatta', 'alert', 'zeropaper-production-189276342382', 'classification', 'vpn audit', 'netcat', 'emails', 'account', 'connectivity', 'pen-544', 'pen-543', 'pen-541', 'ipn', 'fdr', 'jjt', 'penetration testing', '4.2_sbg_penetration testing', 'qicr_sbg_', 'world wide', 'security review', 'clarify', 'approved', 'comment', 'fwd', 'pattern for', 'acl', 'scans', 'scan', 'prod account', 'fraud', 'central', 'receiving', 'polymorphic', 'grades', 'web/app', 'mod_proxy', 'cumulus', 'skyport', 'idps', 'bofa', 'infection-match', 'team', 'non-Intuit', 'windows ami', 'qbo payments', 'scam', 'qsa', 'subramanians', 'hacking', 'cfn', 'appliances', 'account/vpc', 'plane', 'point of sales', 'rango', 'qbx', 'code review', 'attack map', 'architecture consulting', 'amex', 'recertification', 'geographies', 'may 2016', 'qbdt core', 'service_sbg_penetration testing', 'authx_sbg_pentration', 'virus', 'splitting', 'oauth2', 'rasp', 'dynamic', 'invitbox - web application penetration testing', 'template printing service', 'icn chat', 'icnemail', 'icn routing', 'p1', 'acrede penetration testing', 'demandforce bp', 'ezpos', 'devx', 'v3.6', 'v3.7', '3.8', 'qb accountant penetration testing', 'qbo self-employed', 'gen1/2', 'quickBooks self-employed', 'quick books desktop', 'android penetration', 'aayroll api', 'qboa to qba', 'zeropaper penetration', 'financing penetration testing', 'hummingbird', 'maya', '2015 penetration testing', 'sbg_whitehat_penetration']
    aws_account_search = ['stale', 'account audit', 'tenancy', 'iam', 'ec2-user']
    click_jacking_search = ['clickjacking', 'click jacking']
    dos_search = ['dos', 'denial of service']
    ukvc_search = ['using known vulnerable component', 'struts2', 'jquery', 'tomcat', 'wordpress vulnerability', 'machine', 'struts', 'multiple', 'wannacry', 'hygiene', 'apache http', 'vulnerabilities', 'javaScript', 'multiple wordpress', 'vulnerable wordpress', 'restack', 'base ami', 'sequence', 'obsolete', 'java updates', 'ghost2', 'ghost', 'shellshock', 'older', 'old amis','months', 'muira', 'phonegap', 'cordova', 'microsoft', 'outdated']
    # To find the defects category based on the summary
    for rows in range(number_of_rows):
        for columns in range(number_of_columns):
            if any (x in str(sheet.cell(rows,columns)).lower() for x in sql_injection_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                sqli_key.append(result)
                no_sqli_issues +=1
                sql_file = open('sql injection.txt','a+')
                sql_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in xss_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                xss_key.append(result)
                no_xss_issues +=1
                xss_file = open('xss.txt','a+')
                xss_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in remote_injection_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                remote_injection_key.append(result)
                no_remote_injection_issues +=1
                remote_injection_file = open('rce.txt','a+')
                remote_injection_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in ukvc_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                ukvc_key.append(result)
                no_ukvc_issues +=1
                ukvc_file = open('ukvc.txt','a+')
                ukvc_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in idor_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                idor_key.append(result)
                no_idor_issues +=1
                idor_file = open('idor.txt','a+')
                idor_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in broken_authentication_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                broken_authentication_key.append(result)
                no_broken_authentication_issues +=1
                broken_authentication_file = open('broken authentication.txt','a+')
                broken_authentication_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in csrf_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                csrf_key.append(result)
                no_csrf_issues +=1
                csrf_file = open('csrf.txt','a+')
                csrf_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in xml_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                xml_key.append(result)
                no_xml_issues +=1
                xml_file = open('xml.txt','a+')
                xml_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in s3_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                s3_key.append(result)
                no_s3_issues +=1
                s3_file = open('s3.txt','a+')
                s3_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in security_misconfiguration_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                security_misconfiguration_key.append(result)
                no_security_misconfiguration_issues +=1
                security_misconfiguration_file = open('security misconfiguration.txt','a+')
                security_misconfiguration_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in sensitive_data_exposure_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                sensitive_data_exposure_key.append(result)
                no_sensitive_data_exposure_issues +=1
                sensitive_data_exposure_file = open('sensitive data exposure.txt','a+')
                sensitive_data_exposure_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in open_redirection_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                open_redirection_key.append(result)
                no_open_redirection_issues +=1
                open_redirection_file = open('open redirection.txt','a+')
                open_redirection_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in other_security_issue_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                other_security_issue_key.append(result)
                no_other_security_issues +=1
                other_security_issue_file = open('other security issue.txt','a+')
                other_security_issue_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in missing_functional_level_access_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                missing_functional_level_access_key.append(result)
                no_missing_functional_level_access_issues +=1
                missing_functional_level_access_file = open('missing function level access.txt','a+')
                missing_functional_level_access_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in aws_account_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                aws_account_key.append(result)
                no_aws_account_issues +=1
                aws_account_file = open('aws account.txt','a+')
                aws_account_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in click_jacking_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                click_jacking_key.append(result)
                no_click_jacking_issues +=1
                click_jacking_file = open('click jacking.txt','a+')
                click_jacking_file.write(result+'\n')
                break
            elif any (x in str(sheet.cell(rows,columns)).lower() for x in dos_search):
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                dos_key.append(result)
                no_dos_issues +=1
                dos_file = open('dos.txt','a+')
                dos_file.write(result+'\n')
                break
            else:
                a = str(sheet.cell(rows,1))
                result = a.strip("text:'")
                no_category_key.append(result)
                no_no_category_issues +=1
                no_category_file = open('no category.txt', 'a+')
                no_category_file.write(result+'\n')
                break
    # To print out the total number of defects with respect to the vulnerabilities category
    print("{0} sql injection issues found and the tickets are {1}".format(no_sqli_issues,sqli_key))
    print("{0} xss issues found and the tickets are {1}".format(no_xss_issues,xss_key))
    print("{0} remote code execution issues found and the tickets are {1}".format(no_remote_injection_issues,remote_injection_key))
    print("{0} use of known vulnerable components issues found and the tickets are {1}".format(no_ukvc_issues,ukvc_key))
    print("{0} IDOR issues found and the tickets are {1}".format(no_idor_issues,idor_key))
    print("{0} broken authentication issues found and the tickets are {1}".format(no_broken_authentication_issues,broken_authentication_key))
    print("{0} csrf issues found and the tickets are {1}".format(no_csrf_issues,csrf_key))
    print("{0} xml issues found and the tickets are {1}".format(no_xml_issues,xml_key))
    print("{0} s3 issues found and the tickets are {1}".format(no_s3_issues,s3_key))
    print("{0} security misconfiguration issues found and the tickets are {1}".format(no_security_misconfiguration_issues,security_misconfiguration_key))
    print("{0} sensitive data leakage issues found and the tickets are {1}".format(no_sensitive_data_exposure_issues,sensitive_data_exposure_key))
    print("{0} open redirection issues found and the tickets are {1}".format(no_open_redirection_issues,open_redirection_key))
    print("{0} other security issues found and the tickets are {1}".format(no_other_security_issues,other_security_issue_key))
    print("{0} missing functional level access control issues found and the tickets are {1}".format(no_missing_functional_level_access_issues,missing_functional_level_access_key))
    print("{0} aws account issues found and the tickets are {1}".format(no_aws_account_issues,aws_account_key))
    print("{0} click jacking issues found and the tickets are {1}".format(no_click_jacking_issues,click_jacking_key))
    print("{0} DoS issues found and the tickets are {1}".format(no_dos_issues,dos_key))
    print("{0} no category issues found and the tickets are {1}".format(no_no_category_issues,no_category_key))

final_result = classification()
print(final_result)
