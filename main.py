import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description='HTML Vulnerability Analyzer Version 1.0')
 
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help='The URL of HTML to analyze')
parser.add_argument('--config', help='Path to configuration file')
 
args = parser.parse_args()

config = {'forms': True, 'comments': True, 'passwords': True}
 
if(args.config):
  print('Using config file: ' + args.config)
  config_file = open(args.config, 'r')
  config_from_file = yaml.load(config_file)
  if(config_from_file):
    config = config_from_file

url = args.url
report = ''

if(validators.url(url)):

	print('Ok, URL is good!')
	result = requests.get(url).text
	parsed_html = BeautifulSoup(result, 'html.parser')

	forms			= parsed_html.find_all('form')
	comments	    = parsed_html.find_all(string=lambda text:isinstance(text, Comment))
	password_inputs = parsed_html.find_all('input', {'name' : 'password'})

	print(urlparse(url).scheme)


	# print(forms)
	if(config['forms']):
		for form in forms:
			try:
				if ((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
					report += 'Form issue: Insecure form action ' + form.get('action') + 'was found\n'
				else:
					print('Safety')
			except:
				print('Something go wrong! Sorry :-(')

	if(config['comments']):
		for comment in comments:
			if (comment.find('key') > -1):
				report += 'Comment issue: key was found in HTML comments.\n' + comment[comment.find('key') + '\n']

	if(config['password']):
		for password_input in password_inputs:
			if password_input.get('type') != 'password':
				report += 'Input issue: plain text password input was found.\n'

	print(report)
else:
	print('Please, enter a valid URL.')