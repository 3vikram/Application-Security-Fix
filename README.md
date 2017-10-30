# Application-Security-Fix
This repo consists of fixes for Application security vulnerabilities for different platforms

NoSQL Injection (VUlnerable app practice)

https://github.com/websecurify/acme-no-login
https://github.com/websecurify/acme-no-login-ng

XXE (Xerces 1)

http://xerces.apache.org/xerces-j/features.html#external-general-entities

XXE (Xerces 2)

http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl

XML Document explination

1. <!DOCTYPE foo [<!ELEMENT foo ANY >  

(External DTD definition named foo) and ELEMENT foo ANY means DTD can contain any combination of parsable data.

2. <!ENTITY bar SYSTEM "file:///etc/passwd" >]> 

Finally we use the XML declaration ENTITY to load additional data from an external resource.
SYSTEM - The word, SYSTEM, is used to identify the URI (Universal Resource Identifier) of the associated name. The location may be local or include a complete URL

Internal Entity example, <!ENTITY Name "value"> 

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY bar SYSTEM "file:///etc/passwd" >]>
<foo>&bar;</foo>
