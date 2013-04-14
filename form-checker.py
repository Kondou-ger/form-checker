#!/usr/bin/python3
#encoding: utf-8

import sys
import argparse
import http.client
import urllib.parse
import urllib.request
import urllib.error
import re

verbose = False
vulnerable = [[False],[False]] # vulnerable[0]: xss vulnerable[1]: sql
site = ""

xssstring = ["<h1>Hello!</h1>","%3Ch1%3EHello%21%3C%2Fh1%3E"] #[0] <-- plain; [1] <-- URL-encoded
sqlstring = ["<h1>SQL-Injection</h1>","' UNION SELECT '<h1>SQL-Injection</h1>'; -- ","%27%20UNION%20SELECT%20%27<h1>SQL-Injection<%2Fh1>%27%3B%20--%20"] # [0] <- Expected result, [1] <- Query, [2] Query URL-encoded

def main(argv):
	"""
	Takes CLI-Arguments, and runs the program.
	"""

	parser = argparse.ArgumentParser(description="..::Form-Checker::.. \n Check websites for XSS and SQL-Injection. ATTENTION: You must only use this program with permission or on own sites! The developers are not responsible for any damages!")
	parser.add_argument("Site", type=str, help="Website to attack formatted like this: 'http://www.example.com/test.php'")
	parser.add_argument("-c","--check", help="Check Site completely", action="store_true")
	parser.add_argument("-x", "--xss", help="Check site for XSS vulnerabilities", action="store_true")
	parser.add_argument("-s", "--sql", help="Check site for SQL-Injections", action="store_true")
	parser.add_argument("-v", "--verbose", help="Be verbose", action="store_true")
	args = parser.parse_args()
	
	global site
	site = args.Site
	
	if args.verbose:
		global verbose
		verbose = True

	if args.check:
		forms = scansite()
		get_check(forms[0], 1)
		post_check(forms[1], 1)
		after_scan()
	elif args.xss:
		forms = scansite()
		get_check(forms[0], 0)
		post_check(forms[1], 0)
		after_scan()
	elif args.sql:
		forms = scansite()
		get_check(forms[0], 2)
		post_check(forms[1], 2)
		after_scan()
	else:
		print("No valid parameters!")

	return

def scansite():
	"""
	Checks site for GET and POST forms.
	Variablenames will be written in a tuple/list (one for GET/POST).
	These will then be checked for vulnerabilities.
	
	returns two lists, list[0] for GET forms, list[1] for POST forms.
	These lists are seperated again for each form.
	First string of each form is "action" (where should the data go to).
	Example:
	[ [ ["http://www.example.com/", "querystring", "querynum"], ["http://www.example.com/", "querysearch"] ],
	[ ["http://www.example.com/login.php", "username", "password"], ["http://www.example.com/avatar.php", "file", "avatar"] ] ]
	"""
	if showcase:
		print("Splitting websitestring")
	url = urllib.parse.urlparse(site)
	host = url.hostname
	path = url.path
	port = url.port
	if not url.scheme or not host:
		print("URL must be like \"http://domain.tld/document.html\".")
		sys.exit(2)
	
	print_if_showcase("Checking if website is online")
	
	conn = http.client.HTTPConnection(host, port)
	try:
		f = conn.request("GET", path)
	except:
		print("Server down")
		sys.exit(2)
	
	req = urllib.request.Request(site)
	
	try:
		resp = urllib.request.urlopen(req)
	except urllib.error.HTTPError as hndl:
		resp = hndl
		if showcase:
			print("Attention! Error-Page %s!" % hndl.code)
	
	try:
		resp = resp.read()
	except:
		print("Page invalid! \nURL correct?")
		sys.exit(2)
	page = textdecode(resp)

	if showcase:
		print("Analyzing website for forms")

	if page.find("<form",0) == -1:
		print("No forms on this site.")
		sys.exit(1)

	forms = [ [], [] ]
	for formstart in [form.start() for form in re.finditer("<form", page)]:
		thisform = []
		formend = page.find("</form>", formstart)
		form = page[formstart:formend+7]
		method = re.findall(r"[Pp]ost|[Gg]et|POST|GET", form)[0]
		action = re.findall(r"action=[\"'].+?[\"']", form)[0][8:-1]
		thisform.append(action)
		# Search forms with a regex and write them in forms
		for inputstart in [inputfield.start() for inputfield in re.finditer("<input", form)]:
			inputend = form.find(">", inputstart)
			inputtag = form[inputstart:inputend+1]
			rawname = re.findall(r"name=\".+?\"", inputtag)
			if rawname != []: # if rawname == [] -> No name tag -> No input possible (type=submit, e.g.)
				name = rawname[0][6:-1]
				thisform.append(name)
		if method in ["get", "Get", "GET"]:
			forms[0].append(thisform)
		elif method in ["post", "Post", "POST"]:
			forms[1].append(thisform)
		
	conn.close()

	print_if_showcase("Found forms:\n", forms)
	return forms

def get_check(varlist, i):

	print_if_showcase("Checking GET-forms for XSS- and/or SQL-injections.")
	while i <= 2:
		for form in varlist:
			if urllib.parse.urlparse(form[0]).hostname: # If action is a full URL ...
				url = urllib.parse.urlparse(form[0])
				path = url.path + "?"
			else: # ... otherwise we point to the website itself (e.g. action="/search.php")
				url = urllib.parse.urlparse(site)
				path = form[0] + "?"
				if "/" not in path:
					path = "/" + path

			host = url.hostname
			port = url.port
			for name in form[1:]:
				if i == 1 or i== 0:
					path = path + name + "=" + xssstring[1] + "&" # XSS-string with & for next parameter (works ...)
				else:
					path = path + name + "=" + sqlstring[2] + "&"
			conn = http.client.HTTPConnection(host, port)
			if i == 1 or i == 0:
				print_if_showcase("Sending XSS strings")
			else:
				print_if_showcase("Sending SQL strings") 
			conn.request("GET", path)
			check_success(textdecode(conn.getresponse().read()), form, i)
			conn.close()
		if i != 0:
			i = i + 1
		else:
			break

	return
	
def post_check(varlist, i):

	print_if_showcase("Checking POST-forms for XSS- and/or SQL-injections.")
	while i <= 2:
		for form in varlist:
			if i == 1 or i == 0:
				print_if_showcase("Sending XSS strings")
			else:
				print_if_showcase("Sending SQL strings")

			url = urllib.parse.urlparse(site)
			if form[0] not in url.query: # If the website has a query ...
				if form[0] in url.path:  # see if action is in path so it won't be set twice
					link = url.scheme + "://" + url.hostname + url.path
				else:
					link = url.scheme + "://" + url.hostname + url.path + form[0]

			if i == 1 or i == 0:	
				data = urllib.parse.urlencode({form[1]:xssstring[0]})
			else:
				data = urllib.parse.urlencode({form[1]:sqlstring[1]})
			data = textdecode(data)
			req = urllib.request.Request(link)
			req.add_header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
			req.add_header("Referer", "http://www.google.it/")
			req.add_header("Content-Type", "application/x-www-form-urlencoded")

			try:
				hndl = urllib.request.urlopen(req, data)
			except urllib.error.HTTPError as hndl:
				hndl = hndl.read()
			
			try:
				resp = hndl.read()
			except:
				print("Page invalid!\nURL correct?")
				sys.exit(2)
			page = textdecode(resp)

			check_success(page, form, i)

		if i != 0:
			i = i+1
		else:
			break

	return


def check_success(source, form, i):
	"""
	Checks if vulnerability-test was succesfull.
	"""

	global vulnerable

	if i <= 1:
		print_if_showcase("Checking if XSS succesfull")

		if xssstring[0] not in source:
			print_if_showcase("XSS not possible!" )
		else:
			print_if_showcase("XSS succesfull at form %s!" % form)
			vulnerable[0][0] = True
			vulnerable[0].append(form[1])

	if i >= 1:
		print_if_showcase("Checking if SQL-injection succesfull")

		if sqlstring[0] in source and " UNION SELECT " not in source:
			print_if_showcase("SQL-injection succesfull at form %s!" % form)
			vulnerable[1][0] = True
			vulnerable[1].append(form[1])
		else:
			print_if_showcase("SQL-injection not possible!" )


def after_scan():
	"""
	Summarizes scan, prints a short status report.
	"""
	print("\n----------- Status report -----------")
	if vulnerable[0][0] == True:
		print("\nThe website is vulnerable for XSS at following forms: ") # Insert helpfull text here
		print(vulnerable[0][1:])
	if vulnerable[1][0] == True:
		print("\nThe website is vulnerable for SQL-injections at following forms: ") # Insert helpfull text here
		print(vulnerable[1][1:],"\n")
	if vulnerable[0][0] == False and vulnerable[1][0] == False:
		print("\nThis tool thinks the website is not vulnerable.\n")

def textdecode(data):
	"""
	Decodes bytes to strings.
	atm only work with UTF-8 and ISO-8859-1.
	SHIFT-JIS and ISO-8859-9 are not (good) functioning!
	"""
	try:
		page = data.decode('utf-8') # UTF-8
	except UnicodeDecodeError:
		try:
			page = data.decode('iso-8859-1') # ISO-8859-1
		except:
			print("Not supported encoding!")
			print("Are you sure, this is a (international) HTML-website?")
			print("Website:", data[:200])
	return page

def print_if_showcase(string):
	if showcase:
		print(string)

if __name__ == "__main__":
	main(sys.argv[1:])
