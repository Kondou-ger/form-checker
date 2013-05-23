form-checker
============

A small Python3 script, used to analyze websites for SQL-Injection or XSS vulnerabilities. This started out as a computer science project, but we decided to put it on github.

Do __not__ use this on websites you not have the permission to use it on, as this may cause damage!

--

Some examples:

Check a website:
`./form-checker.py -c "http://mywebsite.com/"`

Only check for XSS and be verbose:
`./form-checker.py -xv "http://myotherwebsite.org/"`
