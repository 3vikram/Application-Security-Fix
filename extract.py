import xlrd

file_location = "test1.xlsx"
workbook = xlrd.open_workbook(file_location)
sheet = workbook.sheet_by_index(0)
print('---------------------------------------------------------------------------')
print ('sheet name is ' + sheet.name)
print('---------------------------------------------------------------------------')
number_of_rows = sheet.nrows
print('---------------------------------------------------------------------------')
print ("number of rows: "+ str(number_of_rows))
number_of_columns = sheet.ncols
print ("number of columns: "+str(number_of_columns))
print ('--------------------------------------------------------------------------')

sqli_key = []
xss_key = []
csv_injection_key = []
idor_key = []
ukvc_key = []
broken_authentication_key = []
csrf_key = []
xxe_key = []
s3_key = []
security_misconfiguration_key = []
sensitive_data_exposure_key = []
open_redirection_key = []
other_security_issue_key = []
print('--------------------------------------------------------------------------')

no_sqli_issues = 0
no_xss_issues = 0
no_csv_injection_issues = 0
no_idor_issues = 0
no_ukvc_issues = 0
no_broken_authentication_issues = 0
no_csrf_issues = 0
no_xxe_issues = 0
no_s3_issues = 0
no_security_misconfiguration_issues = 0
no_sensitive_data_exposure_issues = 0
no_open_redirection_issues = 0
no_other_security_issues = 0
print('--------------------------------------------------------------------------')

sql_injection_search = ['sql']
xss_search = ['xss', 'cross-site scripting', 'cross site scripting', 'reflected', 'stored']
csv_injection_search = ['csv']
ukvc_search = ['using known vulnerable component', 'apache', 'jquery', 'apache', 'tomcat', 'wordpress vulnerability']
idor_search = ['manipulation', 'response', 'traversal', 'lfi', 'local file inclusion']
broken_authentication_search = ['password', 'policy', 'session', 'httponly', 'cookie']
csrf_search = ['csrf', 'cross-site request forgery']
xxe_search = ['xml', 'xxe', 'xpath']
s3_search = ['s3', 'bucket']
security_misconfiguration_search = ['error', 'stack', 'trace', 'path', 'internal', 'listing','default account', 'header','headers', 'class', 'cors']
sensitive_data_exposure_search = ['cache', 'sensitive', 'social', 'ssn', 'mask', 'clear', 'http']
open_redirection_search = ['url', 'redirection']
other_security_issue_search = ['onboard']
for rows in range(number_of_rows):
    for columns in range(number_of_columns):
        if any (x in str(sheet.cell(rows,columns)).lower() for x in sql_injection_search):
            sqli_key.append(sheet.cell(rows,1))
            no_sqli_issues +=1
            sql_file = open('sql injection.txt','a+')
            sql_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in xss_search):
            xss_key.append(sheet.cell(rows,1))
            no_xss_issues +=1
            xss_file = open('xss.txt','a+')
            xss_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in csv_injection_search):
            csv_injection_key.append(sheet.cell(rows,1))
            no_csv_injection_issues +=1
            csv_injection_file = open('csv injection.txt','a+')
            csv_injection_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in ukvc_search):
            ukvc_key.append(sheet.cell(rows,1))
            no_ukvc_issues +=1
            ukvc_file = open('ukvc.txt','a+')
            ukvc_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in idor_search):
            idor_key.append(sheet.cell(rows,1))
            no_idor_issues +=1
            idor_file = open('idor.txt','a+')
            idor_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in broken_authentication_search):
            broken_authentication_key.append(sheet.cell(rows,1))
            no_broken_authentication_issues +=1
            broken_authentication_file = open('broken authentication.txt','a+')
            broken_authentication_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in csrf_search):
            csrf_key.append(sheet.cell(rows,1))
            no_csrf_issues +=1
            csrf_file = open('csrf.txt','a+')
            csrf_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in xxe_search):
            xxe_key.append(sheet.cell(rows,1))
            no_xxe_issues +=1
            xxe_file = open('xxe.txt','a+')
            xxe_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in s3_search):
            s3_key.append(sheet.cell(rows,1))
            no_s3_issues +=1
            s3_file = open('s3.txt','a+')
            s3_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in security_misconfiguration_search):
            security_misconfiguration_key.append(sheet.cell(rows,1))
            no_security_misconfiguration_issues +=1
            security_misconfiguration_file = open('security misconfiguration.txt','a+')
            security_misconfiguration_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in sensitive_data_exposure_search):
            sensitive_data_exposure_key.append(sheet.cell(rows,1))
            no_sensitive_data_exposure_issues +=1
            sensitive_data_exposure_file = open('sensitive data exposure.txt','a+')
            sensitive_data_exposure_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in open_redirection_search):
            open_redirection_key.append(sheet.cell(rows,1))
            no_open_redirection_issues +=1
            open_redirection_file = open('open redirection.txt','a+')
            open_redirection_file.write(str(sheet.cell(rows,1))+'\n')
            continue
        elif any (x in str(sheet.cell(rows,columns)).lower() for x in other_security_issue_search):
            other_security_issue_key.append(sheet.cell(rows,1))
            no_other_security_issues +=1
            other_security_issue_file = open('other security issue.txt','a+')
            other_security_issue_file.write(str(sheet.cell(rows,1))+'\n')
            continue

print("{0} sql injection issues found and the tickets are {1}".format(no_sqli_issues,sqli_key))
print("{0} xss issues found and the tickets are {1}".format(no_xss_issues,xss_key))
print("{0} CSV injection issues found and the tickets are {1}".format(no_csv_injection_issues,csv_injection_key))
print("{0} use of known vulnerable components issues found and the tickets are {1}".format(no_ukvc_issues,ukvc_key))
print("{0} IDOR issues found and the tickets are {1}".format(no_idor_issues,idor_key))
print("{0} broken authentication issues found and the tickets are {1}".format(no_broken_authentication_issues,broken_authentication_key))
print("{0} csrf issues found and the tickets are {1}".format(no_csrf_issues,csrf_key))
print("{0} xxe issues found and the tickets are {1}".format(no_xxe_issues,xxe_key))
print("{0} s3 issues found and the tickets are {1}".format(no_s3_issues,s3_key))
print("{0} security misconfiguration issues found and the tickets are {1}".format(no_security_misconfiguration_issues,security_misconfiguration_key))
print("{0} sensitive data leakage issues found and the tickets are {1}".format(no_sensitive_data_exposure_issues,sensitive_data_exposure_key))
print("{0} open redirection issues found and the tickets are {1}".format(no_open_redirection_issues,open_redirection_key))
print("{0} other security issues found and the tickets are {1}".format(no_other_security_issues,other_security_issue_key))
