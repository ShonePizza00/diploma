import os
import json
from struct import pack
from tabnanny import check
import uuid
from tkinter.filedialog import askdirectory
import datetime
import hashlib
'''
default packages reaction
packages installed not via pip (check local directories)
dependencies check (set of all modules)
'''
FILE_BUFFER_SIZE = 65536

SPDX_CREATION_DATE = datetime.datetime.now()
SPDX_UUID = uuid.uuid4()
SPDX_PROJECT_ROOT_PATH = askdirectory()
SPDX_PROJECT_NAME = SPDX_PROJECT_ROOT_PATH.split('/')[-1]
SPDX_DOCUMENT_NAMESPACE = f"{SPDX_PROJECT_NAME}-{SPDX_UUID}"

SPDX_CHECKSUMS_ALGS_NAMES = [
	"SHA1",
	"SHA256",
	"SHA512",
	"SHA3-256",
	"MD5"
]

sbom_file = {
	"spdxVersion": "SPDX-2.2",
	"dataLicense": "CC0-1.0",
	"SPDXID": "SPDXRef-DOCUMENT",
	"name": f"{SPDX_PROJECT_NAME}",
	"documentNamespace": f"https://spdx.org/spdxdocs/{SPDX_DOCUMENT_NAMESPACE}",
	"creationInfo": {
		"created": f"{SPDX_CREATION_DATE.strftime('%Y-%m-%d %H:%M:%S')}",
		"creators" : [
			"Tool: SPDX-Generator-Diploma-0.1",
			"Organization: Gubkin Russian State University of Oil and Gas"
			]
		},
	"packages": [],
}

sbom_package_body = {
	"name": "",#+
	"SPDXID": "",#+
	"versionInfo": "",#+
	"supplier": "",#+
	"downloadLocation": "NOASSERTION",#+
	"licenseConcluded": "",#+
	"licenseDeclared": "",#+
	"licenseComments": "NOASSERTION",#+
	"copyrightText": "",#+
	"description": "",#+
	"checksums": []#+
}

checksums_package_body = {
	"algorithm": "",
	"checksumValue": ""
}

pip_package_body = {
	"Name": ["name"],
	"Version": ["versionInfo"],
	"Summary": ["description"],
	"License": [
		"licenseConcluded",
		"licenseDeclared"]
}

def parseDefaultPackage(package_name):
	sbom_part = sbom_package_body.copy()
	package_version = os.popen(f'python -V').read().split(' ')[-1]
	sbom_part["name"] = package_name
	sbom_part["SPDXID"] = f"SPDXRef-Package-{hashlib.sha1(f'{package_name}-{package_version}'.encode()).hexdigest()[:16]}"
	sbom_part["versionInfo"] = package_version
	sbom_part["supplier"] = "Organization: The Python Software Foundation"
	sbom_part["downloadLocation"] = f"https://www.python.org/ftp/python/{package_version}/python-{package_version}-amd64.exe"
	sbom_part["licenseConcluded"] = "Python Software Foundation License"
	sbom_part["licenseDeclared"] = "Python Software Foundation License"
	sbom_part["copyrightText"] = f"1. This LICENSE AGREEMENT is between the Python Software Foundation (\"PSF\"), and\nthe Individual or Organization (\"Licensee\") accessing and otherwise using Python\n{package_version} software in source or binary form and its associated documentation.\n2. Subject to the terms and conditions of this License Agreement, PSF hereby\ngrants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,\nanalyze, test, perform and/or display publicly, prepare derivative works,\ndistribute, and otherwise use Python {package_version} alone or in any derivative\nversion, provided, however, that PSF's License Agreement and PSF's notice of\ncopyright, i.e., \"Copyright \u00a9 2001-2024 Python Software Foundation; All Rights\nReserved\" are retained in Python {package_version} alone or in any derivative version\nprepared by Licensee.\n3. In the event Licensee prepares a derivative work that is based on or\nincorporates Python {package_version} or any part thereof, and wants to make the\nderivative work available to others as provided herein, then Licensee hereby\nagrees to include in any such work a brief summary of the changes made to Python\n{package_version}.\n4. PSF is making Python {package_version} available to Licensee on an \"AS IS\" basis.\nPSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED.  BY WAY OF\nEXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND DISCLAIMS ANY REPRESENTATION OR\nWARRANTY OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE\nUSE OF PYTHON {package_version} WILL NOT INFRINGE ANY THIRD PARTY RIGHTS.\n5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON {package_version}\nFOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS A RESULT OF\nODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON {package_version}, OR ANY DERIVATIVE\nTHEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.\n6. This License Agreement will automatically terminate upon a material breach of\nits terms and conditions.\n7. Nothing in this License Agreement shall be deemed to create any relationship\nof agency, partnership, or joint venture between PSF and Licensee.  This License\nAgreement does not grant permission to use PSF trademarks or trade name in a\ntrademark sense to endorse or promote products or services of Licensee, or any\nthird party.\n8. By copying, installing or otherwise using Python {package_version}, Licensee agrees\nto be bound by the terms and conditions of this License Agreement."
	sbom_part["description"] = "NOASSERTION"

	
	hash_handlers = [
	hashlib.sha1(),
	hashlib.sha256(),
	hashlib.sha512(),
	hashlib.sha3_256(),
	hashlib.md5()
	]
	for _dir in os.walk(package_location):
		for f in _dir[-1]:
			f_handler = open(f"{_dir[0]}\\{f}", 'rb')
			
			while True:
				data = f_handler.read(FILE_BUFFER_SIZE)
				if (not data):
					f_handler.close()
					break
				for handler in hash_handlers:
					handler.update(data)
	sbom_part["checksums"] = []
	for i in range(len(hash_handlers)):
		checksum_part = checksums_package_body.copy()
		checksum_part["algorithm"] = SPDX_CHECKSUMS_ALGS_NAMES[i]
		checksum_part["checksumValue"] = hash_handlers[i].hexdigest()
		sbom_part["checksums"].append(checksum_part)

	return sbom_part

def parsePackage(package_name):
	a = os.popen(f'pip show {package_name}').read().split('\n')
	sbom_part = sbom_package_body.copy()
	package_author = ""
	package_author_email = ""
	package_location = ""
	if (len(a) == 1):
		sbom_file["packages"].append(parseDefaultPackage(package_name))
		return

	for i in range(len(a)):
		t = a[i].split(':', 1)
		t[-1] = t[-1].lstrip(' ').rstrip(' ')
		if (t[-1] == ""): t[-1] = "NOASSERTION"
		if (t[0] == "Author"): package_author = t[-1]
		if (t[0] == "Author-email"): package_author_email = t[-1]
		if (t[0] == "Location"): package_location = t[-1]
		if (t[0] in pip_package_body):
			if (len(pip_package_body[t[0]]) == 1):
				sbom_part[pip_package_body[t[0]][0]] = t[-1]
			else:
				for item in pip_package_body[t[0]]:
					sbom_part[item] = t[-1]
	package_version = sbom_part["versionInfo"]
	sbom_part["SPDXID"] = f"SPDXRef-Package-{hashlib.sha1(f'{package_name}-{package_version}'.encode()).hexdigest()[:16]}"
	if (package_author == "NOASSERTION"):
		if (package_author_email == "NOASSERTION"):
			sbom_part["supplier"] = "NOASSERTION"
		else:
			t2 = package_author_email.split(' ')
			sbom_part["supplier"] = f"Person: {' '.join(t2[:2])} ({t2[-1].lstrip('<').rstrip('>')})"
	else:
		if (package_author_email == "NOASSERTION"):
			if ('@' in package_author):
				t2 = package_author.split(' ')
				sbom_part["supplier"] = f"Person: {' '.join(t2[:2])} ({t2[-1].lstrip('<').rstrip('>')})"
			else:
				sbom_part["supplier"] = f"Person: {package_author} ({package_author_email.lstrip('<').rstrip('>')})"
		else:
			sbom_part["supplier"] = f"Person: {package_author} ({package_author_email.lstrip('<').rstrip('>')})"
	package_location += f"\\{package_name}"
	package_dist_info_location = package_location + f"-{package_version}.dist-info\\"
	license_file_location = ""
	for _dir in os.walk(package_dist_info_location):
		for f in _dir[-1]:
			if ("LICENSE" in f.upper()):
				license_file_location = f"{_dir[0]}\\{f}"
	try:
		f = open(license_file_location)
		license_file_content = f.read()
		f.close()
		flag1 = False
		if (sbom_part["licenseConcluded"] == "NOASSERTION"):
			flag1 = True
		t1 = license_file_content.split('\n')
		index_begin = 0
		index_end = len(t1) - 1
		for line in range(len(t1)):
			if ("BEGIN LICENSE BLOCK" in t1[line]):
				index_begin = line + 1
			if ("END LICENSE BLOCK" in t1[line]):
				index_end = line
		if (flag1):
			sbom_part["licenseDeclared"] = t1[index_begin].lstrip(' ').rstrip(' ')
			sbom_part["licenseComments"] = f"The license is automatically exported from the file {license_file_location}."
		license_file_content = "\n".join(t1[index_begin:index_end])
		sbom_part["copyrightText"] = license_file_content
	except:
		sbom_part["licenseComments"] = "The license not found."
		sbom_part["copyrightText"] = "NOASSERTION"	

	hash_handlers = [
	hashlib.sha1(),
	hashlib.sha256(),
	hashlib.sha512(),
	hashlib.sha3_256(),
	hashlib.md5()
	]
	for _dir in os.walk(package_location):
		for f in _dir[-1]:
			f_handler = open(f"{_dir[0]}\\{f}", 'rb')
			
			while True:
				data = f_handler.read(FILE_BUFFER_SIZE)
				if (not data):
					f_handler.close()
					break
				for handler in hash_handlers:
					handler.update(data)
	sbom_part["checksums"] = []
	for i in range(len(hash_handlers)):
		checksum_part = checksums_package_body.copy()
		checksum_part["algorithm"] = SPDX_CHECKSUMS_ALGS_NAMES[i]
		checksum_part["checksumValue"] = hash_handlers[i].hexdigest()
		sbom_part["checksums"].append(checksum_part)
	sbom_file["packages"].append(sbom_part)
	return
	
parsePackage('requests')
parsePackage('certifi')
parsePackage('urllib3')
parsePackage('os')
#sbom_file[PACKAGES_NAME].append(package_json("requests"))

print(json.dumps(sbom_file, indent=4))

