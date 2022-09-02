# Beskar
The Couchbase Server security scanner

##Install Python Dependencies
pip3 install -r requirements.txt

##Generate CVE JSON file

curl 'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeName=cpe:2.3:a:couchbase:couchbase_server:*:*:*:*:*:*:*:*&resultsPerPage=100' > cbserver-cves.json

##Run the tool
python3 beskar.py
