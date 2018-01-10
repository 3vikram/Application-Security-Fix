import xlrd
import xlsxwriter
import os
from jira import JIRA

def defects():
    # Login using corp credentials
    user_name = input("Enter your corp credentials: ")
    password = input("Enter your corp password: ")
    jira_query = input("Enter the jira jql query: ")
    #Authentication
    login_credentials = JIRA(basic_auth=(user_name, password), options={'server': 'https://jira.intuit.com'})
    jql_query = jira_query

    # Delete files every time at the start having Issue Keys
    if os.path.isfile("./injection.txt"):
        os.remove("./injection.txt")
    if os.path.isfile("./xss.txt"):
        os.remove("./xss.txt")
    if os.path.isfile("./rce.txt"):
        os.remove("./rce.txt")
    if os.path.isfile("./vulnerable components.txt"):
        os.remove("./vulnerable components.txt")
    if os.path.isfile("./broken access control.txt"):
        os.remove("./broken access control.txt")
    if os.path.isfile("./broken authentication.txt"):
        os.remove("./broken authentication.txt")
    if os.path.isfile("./csrf.txt"):
        os.remove("./csrf.txt")
    if os.path.isfile("./s3.txt"):
        os.remove("./s3.txt")
    if os.path.isfile("./security misconfiguration.txt"):
        os.remove("./security misconfiguration.txt")
    if os.path.isfile("./sensitive data exposure.txt"):
        os.remove("./sensitive data exposure.txt")
    if os.path.isfile("./open redirection.txt"):
        os.remove("./open redirection.txt")
    if os.path.isfile("./other security issue.txt"):
        os.remove("./other security issue.txt")
    if os.path.isfile("./iam.txt"):
        os.remove("./iam.txt")
    if os.path.isfile("./dos.txt"):
        os.remove("./dos.txt")
    if os.path.isfile("./xxe.txt"):
        os.remove("./xxe.txt")
    if os.path.isfile("./ec2.txt"):
        os.remove("./ec2.txt")
    if os.path.isfile("./logging and monitoring.txt"):
        os.remove("./logging and monitoring.txt")
    if os.path.isfile("./insecure deserialization.txt"):
        os.remove("./insecure deserialization.txt")
    if os.path.isfile("./unrestricted fileupload download.txt"):
        os.remove("./unrestricted fileupload download.txt")
    if os.path.isfile("./over flow.txt"):
        os.remove("./over flow.txt")
    if os.path.isfile("./code tampering.txt"):
        os.remove("./code tampering.txt")
    if os.path.isfile("./reverse engineering.txt"):
        os.remove("./reverse engineering.txt")
    if os.path.isfile("./none.txt"):
        os.remove("./none.txt")
    if os.path.isfile("./ami.txt"):
        os.remove("./ami.txt")
    if os.path.isfile("./Defects_list.xls"):
        os.remove("./Defects_list.xls")

# List of keywords to search for vulnerabilities by category
    block_size = 200
    block_numb = 0
    length = 0
    workbook = xlsxwriter.Workbook('Defects_list.xls')
    worksheet = workbook.add_worksheet()
    rows = 0
    cols = 0
    while True:
        start_index = block_numb*block_size
        issues_id = login_credentials.search_issues(jql_str=jql_query, startAt=start_index, maxResults=block_size)
        length +=len(issues_id)
        if len(issues_id) == 0:
            break
        block_numb +=1
        for defects in issues_id:
            issue_key = defects
            summary = issue_key.fields.summary
            print('%s: %s'%(issue_key, summary))
            worksheet.write(rows,cols,str(summary))
            worksheet.write(rows,cols+1,str(defects))
            rows +=1
        print("--------------------------------------------------------------------------------------------------------------------------------")
    no_injection = 0
    no_open_redirection = 0
    no_xss = 0
    no_remote_code_execution = 0
    no_broken_Access_Control = 0
    no_broken_authentication = 0
    no_csrf = 0
    no_xxe = 0
    no_s3 = 0
    no_security_misconfiguration = 0
    no_sensitive_data_exposure = 0
    no_other_security = 0
    no_iam = 0
    no_ec2 = 0
    no_dos = 0
    no_vulnerable_components = 0
    no_logging_monitoring = 0
    no_insecure_deserialization = 0
    no_unrestricted_fileupload_download = 0
    no_over_flow = 0
    no_code_tampering = 0
    no_reverse_engineering = 0
    no_none = 0
    no_ami = 0
    injection_key = []
    open_redirection_key = []
    xss_key = []
    remote_code_execution_key = []
    broken_Access_Control_key = []
    broken_authentication_key = []
    csrf_key = []
    xxe_key = []
    s3_key = []
    security_misconfiguration_key = []
    sensitive_data_exposure_key = []
    other_security_issue_key = []
    iam_key = []
    ec2_key = []
    dos_key = []
    vulnerable_components_key = []
    logging_monitoring_key = []
    insecure_deserialization_key = []
    unrestricted_fileupload_download_key = []
    over_flow_key = []
    code_tampering_key = []
    reverse_engineering_key = []
    none_key = []
    ami_key = []
    injection = ['sql injection', 'ldap injection', 'xpath injection', 'csv', 'command injection', 'text injection']
    open_redirection = ['url redirector abuse' ,'unvalidated' ,'forwards', 'url redirector abuse', 'unvalidated redirect', 'openid', 'redirect', 'unvalidated url']
    xss = ['xss', 'cross-site scripting', 'cross site scripting', 'cross side scripting','reflected', 'stored', 'input validation', 'input handling', 'sanitized']
    remote_code_execution = ['remote code execution', 'xauth', 'teemu', '.qbw', 'commands', 'silently']
    broken_Access_Control = ['manipulation', 'response', 'traversal', 'lfi', 'local file inclusion', 'business logic flaw', 'pollution', 'inclusion', 'reference', 'insecure direct object reference', 'spoofing', 'authorization', 'authenticate', '0-day', 'missing', 'a7', 'bypass', 'non-admin', 'ifsp', 'failure', 'faliure', 'abuse of functionality', 'unattended', 'missing function level access control', 'anonymous', 'auth', 'escalation', 'touchid', 'keychain', 'permission', 'exported', 'hidden', 'risk065']
    broken_authentication = ['password', 'policy', 'session', 'httponly', 'cookie', 'rotate', 'flag', 'authentication', 'rotated', 'recaptcha', 'anti-automation', 'pci-sensitive', 'broken', 'locking', 'lockout', 'bruteforce', 'rate limiting', 'brute force', 'brute-force', 'ticket', 'enumration', 'autocomplete', 'oauth2', 'timeout']
    csrf = ['csrf', 'cross-site request forgery', 'cross site request forgery', 'fixation']
    xxe = ['entity', 'xxe', 'xpath', 'bomb', 'billion', 'laughs', 'xml']
    s3 = ['s3', 'bucket']
    security_misconfiguration = ['error', 'keytab', 'stack', 'trace', 'path', 'internal', 'listing','default account', 'header', 'headers', 'class', 'cors', 'suspicious', 'nginx', 'host header', 'windows remote', 'relies', 'poxy', 'track', 'rds', 'management console', 'group', 'jmx', 'ornange', 'subdomain', 'options method', 'cross-origin resource sharing', 'cross origin resource sharing', 'restored', 'ftp', 'sftp', 'apache', 'ssh', 'entries', 'cleanup', 'jboss', 'everyone', 'rouge', 'exploitation', 'take-over', 'take over', 'customer downloads', 'lack of controls', 'sql_read', 'vpc flow', 'sniffing', 'inserting', 'cloudtrail', 'unresolved', 'mobile gateway', '3821', 'kaos', 'slow', 'crossdomain.xml', 'debug', 'debugger', '62026', 'fingerprinting', 'allaire', 'attachments', 'violation', 'deprecated', 'realm', 'listable', 'banner', 'multiple security', 'predictable resource', 'relay', 'deployment', 'server misconfiguration', 'jenkins', 'rundeck', 'peering', '03/02/2016', 'encrypted', 'robots.txt', 'misconfiguration', 'apple', 'referal', 'detection', 'jailbreak', 'indexing', 'orangehrm', '199.187.158.195', '199.187.158.196', '199.16.142.42', '12.149.173.50', 'abused', 'flood', 'proxy', 'pos-build', 'clickjacking', 'click jacking', 'webserver information']
    sensitive_data_exposure = ['cipher','cache', 'sensitive', 'social', 'ssn', 'mask', 'clear', 'plain', 'http', 'ssl', 'rc4', 'swagger', 'tls', 'cachable', 'cacheable', 'strict', 'internal ip', 'wsdl', 'secrets', 'disclosure', 'secret', 'private auth', 'exposed', 'data handling', 'privateAuth+', 'birthday', 'confidential', 'exposure', 'exposing', 'leakage', 'transport', 'certificate', 'encryption', 'oauth', 'null', 'hashing', 'hash', 'certificates', 'unencrypted', 'communication', 'cbc', 'cbc3', 'plain-text', 'credentials', 'credential', 'key', 'keys', 're-keying', 'android:application', 'pinning', 'unmasked', 'cached', 'caching', 'pii', 'transfer', 'manifest', 'binary', 'compiler', 'wifi', 'bluetooth', 'nfc', 'gsm', 'sms', '3g', 'audio', 'ciphers']
    other_security = ['onboard', 'other', 'jira-python', 'blocked', '404 alerts', 'aggregation', 'recon check', 'whitelist', 'whitelisting', 'whitelisted', 'regulatory', 'mightybell', 'fundbox', 'vyatta', 'alert', 'zeropaper-production-189276342382', 'classification', 'vpn audit', 'netcat', 'emails', 'account', 'connectivity', 'pen-544', 'pen-543', 'pen-541', 'ipn', 'fdr', 'jjt', 'penetration testing', '4.2_sbg_penetration testing', 'qicr_sbg_', 'world wide', 'security review', 'clarify', 'approved', 'comment', 'fwd', 'pattern for', 'prod account', 'central', 'receiving', 'polymorphic', 'grades', 'web/app', 'mod_proxy', 'cumulus', 'skyport', 'idps', 'bofa', 'infection-match', 'team', 'non-Intuit', 'qbo payments', 'qsa', 'subramanians', 'hacking', 'cfn', 'appliances', 'account/vpc', 'plane', 'point of sales', 'rango', 'qbx', 'code review', 'attack map', 'architecture consulting', 'amex', 'recertification', 'geographies', 'may 2016', 'qbdt core', 'service_sbg_penetration testing', 'authx_sbg_pentration', 'splitting', 'rasp', 'dynamic', 'invitbox - web application penetration testing', 'template printing service', 'icn chat', 'icnemail', 'icn routing', 'p1', 'acrede penetration testing', 'demandforce bp', 'ezpos', 'devx', 'v3.6', 'v3.7', '3.8', 'qb accountant penetration testing', 'qbo self-employed', 'gen1/2', 'quickBooks self-employed', 'quick books desktop', 'android penetration', 'aayroll api', 'qboa to qba', 'zeropaper penetration', 'financing penetration testing', 'hummingbird', 'maya', '2015 penetration testing', 'sbg_whitehat_penetration']
    iam = ['stale', 'account audit', 'tenancy', 'iam', 'mfa', '203325998673']
    ec2 = ['ec2-user', 'ec2']
    dos = ['dos', 'denial of service']
    vulnerable_components = ['using component with known vulnerabilites', 'using known vulnerable component', 'struts2', 'jquery', 'tomcat', 'wordpress vulnerability', 'machine', 'struts', 'multiple', 'wannacry', 'hygiene', 'apache http', 'vulnerabilities', 'javascript', 'multiple wordpress', 'vulnerable wordpress', 'restack', 'sequence', 'obsolete', 'java updates', 'ghost2', 'ghost', 'shellshock', 'older','months', 'muira', 'phonegap', 'cordova', 'microsoft', 'outdated', 'heartbleed', 'poodle', 'freak', 'reconcheck']
    logging_monitoring = ['monitoring', 'logging', 'virus', 'malware', 'fraud', 'scam', 'acl', 'scans', 'scan', 'non-intuit ip', 'logs']
    insecure_deserialization = ['deserialization']
    unrestricted_fileupload_download = ['uploads', 'upload', 'rfd', 'downloads', 'download', 'unrestricted']
    over_flow = ['buffer', 'integer', 'heap', 'over flow', 'over-flow']
    code_tampering = ['otacerts', 'noshufou', 'superuser', 'chainfire', 'koushikdutta', 'su', 'binaries']
    reverse_engineering = ['string table analysis', 'cross-functional analysis', 'source code analysis', 'obfuscate']
    ami = ['non-intuit ami', 'windows ami', 'base ami', 'old amis']
    workbook.close()
    workbook_1 = xlrd.open_workbook("Defects_list.xls")
    worksheet_1 = workbook_1.sheet_by_index(0)
    total_rows = worksheet_1.nrows
    total_cols = worksheet_1.ncols
    for rows in range(total_rows):
        for cols in range (total_cols):
            if any (x in str(worksheet_1.cell(rows,cols)).lower() for x in injection):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                injection_key.append(found_issue_key)
                no_injection +=1
                injection_file = open('injection.txt','a+')
                injection_file.write(found_issue_key+'\n')
                injection_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in xss):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                xss_key.append(found_issue_key)
                no_xss +=1
                xss_file = open('xss.txt','a+')
                xss_file.write(found_issue_key+'\n')
                xss_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in remote_code_execution):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                remote_code_execution_key.append(found_issue_key)
                no_remote_code_execution +=1
                rce_file = open('rce.txt','a+')
                rce_file.write(found_issue_key+'\n')
                rce_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in vulnerable_components):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                vulnerable_components_key.append(found_issue_key)
                no_vulnerable_components +=1
                vulnerable_components_file = open('vulnerable components.txt','a+')
                vulnerable_components_file.write(found_issue_key+'\n')
                vulnerable_components_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in broken_Access_Control):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                broken_Access_Control_key.append(found_issue_key)
                no_broken_Access_Control +=1
                broken_Access_Control_file = open('broken access control.txt','a+')
                broken_Access_Control_file.write(found_issue_key+'\n')
                broken_Access_Control_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in broken_authentication):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                broken_authentication_key.append(found_issue_key)
                no_broken_authentication +=1
                broken_authentication_file = open('broken authentication.txt','a+')
                broken_authentication_file.write(found_issue_key+'\n')
                broken_authentication_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in csrf):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                csrf_key.append(found_issue_key)
                no_csrf +=1
                csrf_file = open('csrf.txt','a+')
                csrf_file.write(found_issue_key+'\n')
                csrf_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in s3):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                s3_key.append(found_issue_key)
                no_s3 +=1
                s3_file = open('s3.txt','a+')
                s3_file.write(found_issue_key+'\n')
                s3_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in security_misconfiguration):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                security_misconfiguration_key.append(found_issue_key)
                no_security_misconfiguration +=1
                security_misconfiguration_file = open('security misconfiguration.txt','a+')
                security_misconfiguration_file.write(found_issue_key+'\n')
                security_misconfiguration_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in sensitive_data_exposure):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                sensitive_data_exposure_key.append(found_issue_key)
                no_sensitive_data_exposure +=1
                sensitive_data_exposure_file = open('sensitive data exposure.txt','a+')
                sensitive_data_exposure_file.write(found_issue_key+'\n')
                sensitive_data_exposure_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in open_redirection):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                open_redirection_key.append(found_issue_key)
                no_open_redirection +=1
                open_redirection_file = open('open redirection.txt','a+')
                open_redirection_file.write(found_issue_key+'\n')
                open_redirection_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in other_security):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                other_security_issue_key.append(found_issue_key)
                no_other_security +=1
                other_security_issue_file = open('other security issues.txt','a+')
                other_security_issue_file.write(found_issue_key+'\n')
                other_security_issue_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in iam):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                iam_key.append(found_issue_key)
                no_iam +=1
                iam_file = open('iam.txt','a+')
                iam_file.write(found_issue_key+'\n')
                iam_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in dos):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                dos_key.append(found_issue_key)
                no_dos +=1
                dos_file = open('dos.txt','a+')
                dos_file.write(found_issue_key+'\n')
                dos_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in xxe):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                xxe_key.append(found_issue_key)
                no_xxe +=1
                xxe_file = open('xxe.txt','a+')
                xxe_file.write(found_issue_key+'\n')
                xxe_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in ec2):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                ec2_key.append(found_issue_key)
                no_ec2 +=1
                ec2_file = open('ec2.txt','a+')
                ec2_file.write(found_issue_key+'\n')
                ec2_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in logging_monitoring):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                logging_monitoring_key.append(found_issue_key)
                no_logging_monitoring +=1
                logging_monitoring_file = open('logging and monitoring.txt','a+')
                logging_monitoring_file.write(found_issue_key+'\n')
                logging_monitoring_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in insecure_deserialization):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                insecure_deserialization_key.append(found_issue_key)
                no_insecure_deserialization +=1
                insecure_deserialization_file = open('insecure deserialization.txt','a+')
                insecure_deserialization_file.write(found_issue_key+'\n')
                insecure_deserialization_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in unrestricted_fileupload_download):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                unrestricted_fileupload_download_key.append(found_issue_key)
                no_unrestricted_fileupload_download +=1
                unrestricted_fileupload_download_file = open('unrestricted fileupload download.txt','a+')
                unrestricted_fileupload_download_file.write(found_issue_key+'\n')
                unrestricted_fileupload_download_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in over_flow):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                over_flow_key.append(found_issue_key)
                no_over_flow +=1
                over_flow_file = open('over flow.txt','a+')
                over_flow_file.write(found_issue_key+'\n')
                over_flow_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in code_tampering):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                code_tampering_key.append(found_issue_key)
                no_remote_code_execution +=1
                code_tampering_file = open('code tampering.txt','a+')
                code_tampering_file.write(found_issue_key+'\n')
                code_tampering_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in reverse_engineering):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                reverse_engineering_key.append(found_issue_key)
                no_reverse_engineering +=1
                reverse_engineering_file = open('reverse engineering.txt','a+')
                reverse_engineering_file.write(found_issue_key+'\n')
                reverse_engineering_file.close()
                break
            elif any (x in str(worksheet_1.cell(rows,cols)).lower() for x in ami):
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                ami_key.append(found_issue_key)
                no_ami +=1
                ami_file = open('ami.txt','a+')
                ami_file.write(found_issue_key+'\n')
                ami_file.close()
                break
            else:
                found_issue_key = str(worksheet_1.cell(rows,1)).strip("text:'")
                none_key.append(found_issue_key)
                no_none +=1
                none_file = open('none.txt','a+')
                none_file.write(found_issue_key+'\n')
                none_file.close()
                break

    # To print out the total number of defects with respect to the vulnerabilities category
    print("{0} injection issues found and the tickets are {1}".format(no_injection,injection_key))
    print("{0} xss issues found and the tickets are {1}".format(no_xss,xss_key))
    print("{0} remote code execution issues found and the tickets are {1}".format(no_remote_code_execution,remote_code_execution_key))
    print("{0} use of known vulnerable components issues found and the tickets are {1}".format(no_vulnerable_components,vulnerable_components_key))
    print("{0} broken access control issues found and the tickets are {1}".format(no_broken_Access_Control,broken_Access_Control_key))
    print("{0} broken authentication issues found and the tickets are {1}".format(no_broken_authentication,broken_authentication_key))
    print("{0} csrf issues found and the tickets are {1}".format(no_csrf,csrf_key))
    print("{0} xxe issues found and the tickets are {1}".format(no_xxe,xxe_key))
    print("{0} s3 issues found and the tickets are {1}".format(no_s3,s3_key))
    print("{0} security misconfiguration issues found and the tickets are {1}".format(no_security_misconfiguration,security_misconfiguration_key))
    print("{0} sensitive data exposure issues found and the tickets are {1}".format(no_sensitive_data_exposure,sensitive_data_exposure_key))
    print("{0} open redirection issues found and the tickets are {1}".format(no_open_redirection,open_redirection_key))
    print("{0} other security issues found and the tickets are {1}".format(no_other_security,other_security_issue_key))
    print("{0} iam issues found and the tickets are {1}".format(no_iam,iam_key))
    print("{0} dos issues found and the tickets are {1}".format(no_dos,dos_key))
    print("{0} ec2 issues found and the tickets are {1}".format(no_ec2,ec2_key))
    print("{0} Insufficiant logging and monitoring issues found and the tickets are {1}".format(no_logging_monitoring,logging_monitoring_key))
    print("{0} Insecure Deserialization issues found and the tickets are {1}".format(no_insecure_deserialization,insecure_deserialization_key))
    print("{0} Unrestricted FileUpload Download issues found and the tickets are {1}".format(no_unrestricted_fileupload_download,unrestricted_fileupload_download_key))
    print("{0} over flow issues found and the tickets are {1}".format(no_over_flow,over_flow_key))
    print("{0} Code Tampering issues found and the tickets are {1}".format(no_code_tampering,code_tampering_key))
    print("{0} Reverse Engineering issues found and the tickets are {1}".format(no_reverse_engineering,reverse_engineering_key))
    print("{0} ami issues found and the tickets are {1}".format(no_ami,ami_key))
    print("{0} no category issues found and the tickets are {1}".format(no_none,none_key))
    print("---------------------------------------------------------------------------------------------------------------")
    print("Total number of defects in SBGSEC project : {0}".format(length))
    print("---------------------------------------------------------------------------------------------------------------")



execute = defects()
print(execute)




