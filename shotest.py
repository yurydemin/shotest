import shodan
import sys
import argparse

def parser_error(errmsg):
    banner()
    print("Usage: python3 " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
	parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -k api_key -d 127.0.0.1 -o result.txt")
	parser.error = parser_error
	parser._optionals.title = "OPTIONS"
	parser.add_argument('-k', '--key', help="shodan api key", required=True)
	parser.add_argument('-d', '--domain', help="target domain", required=True)
	parser.add_argument('-o', '--output', help="result txt file", required=True)
	return parser.parse_args()
	
# parse the arguments
args = parse_args()
API_KEY = args.key
TARGET = args.domain
OUTPUT = args.output

# Setup the api
api = shodan.Shodan(API_KEY)

# Lookup the host
host = api.host(TARGET)

# Get results
orig_stdout = sys.stdout

with open(OUTPUT, 'w') as f:
	sys.stdout = f
	# Print general info
	print("""
        IP: {}
        Organization: {}
        Operating System: {}
	""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
	# Print all banners
	for item in host['data']:
        	print("""
                Port: {}
                Banner: {}
	        """.format(item['port'], item['data']))
	sys.stdout = orig_stdout
