from datetime import datetime
import pandas as pd
import json
import csv
import argparse
import socket
import os

parser = argparse.ArgumentParser(description='Nuclei Json parser to CSV.')
parser.add_argument('-i', '--input', help='Input file', required=True)
parser.add_argument('-o', '--output', help='Output file', required=True)

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
args = parser.parse_args()
json_file = args.input
csv_file = ROOT_DIR + args.output
print(csv_file)

data_file = open(csv_file, 'w')
csv_writer = csv.writer(data_file)

print("Reading Json file")

vulnerabilities = []

with open(json_file) as json_file:
    for e in json_file:
        data = json.loads(e)
        url = data['host']
        try:
            ip = data['ip']
        except:
            KeyError
            ip = ''
            pass

        print('Vulnerability %s found on: %s' % (data['info']['name'], url))
        try:
            results =  data['extracted-results']
        except:
            KeyError
            results = ''
            pass
        try:
            vector = data['info']['classification']['cvss-metrics']
        except:
            KeyError
            vector = ''
            pass

        try:
            cve = data['info']['classiification']['cve-id']
        except:
            KeyError
            cve = ''
            pass
            
        try:
            cwe = data['info']['classification']['cwe-id']
        except:
            KeyError
            cwe = ''
            pass

        try:
            cvss = data['info']['classification']['cvss-score']
        except:
            KeyError
            cvss = 0
            pass

        try:
            description = data['info']['description']
        except:
            KeyError
            description = ''
            pass

        try:
            curl = data['curl-command']
        except:
            KeyError
            curl = ''
            pass
        
        vuln_to_add = {
            'vulnerability_name': data['info']['name'],
            'host': url,
	     	'endpoint': data['matched-at'],
	     	'ip': data['ip'],
            'observation_title': data['info']['name'],
            'observation': description,
            'observation_note': '',
            'implication': '',
            'recommendation_title': '',
            'recommendation_note': data['info']['reference'],
            'severity': data['info']['severity'].upper(),
            'cvss_score': cvss,
            'attack_vector': vector,
            'cve-id': cve,
            'cwe-id': cwe,
            'curl-command': curl,
            'results': results,
            'date_found': datetime.now(),
            'last_seen': datetime.now(),
            'language': 'eng',
            'vuln_type': 'ip',
            'state': 'new',
            'scope': 'internal',
	    }

      
        vulnerabilities.append(vuln_to_add)
        count = 0
        for vuln in vulnerabilities:
           count += 1

# parse results to a dataframe with headers and index
df = pd.DataFrame(vulnerabilities)
# save dataframe to csv
df.to_csv(csv_file, index=False)
print('Total Vulnerabilities: ', count)
