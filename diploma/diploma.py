import os
import json
import uuid
from tkinter.filedialog import askdirectory
import datetime
import hashlib
import platform
from tree import treeNode
from pipParser import pipParser

FILE_BUFFER_SIZE = 65536


SPDX_LOG_MODE = True
SPDX_CREATION_DATE = datetime.datetime.now()
SPDX_UUID = uuid.uuid4()
print("Select Project folder location")
SPDX_PROJECT_ROOT_PATH = askdirectory().replace('/', '\\')
SPDX_PROJECT_NAME = SPDX_PROJECT_ROOT_PATH.split('\\')[-1]
SPDX_DOCUMENT_NAMESPACE = f"{SPDX_PROJECT_NAME}-{SPDX_UUID}"

OS_NAME_ = ""
SEPARATOR_ = ""
PIP_NAME_ = ""
PYTHON_NAME_ = ""
PIP_NAME_D_ = ""
PYTHON_NAME_D_ = ""
print("Select SBOM file location")
JSON_DUMP_FILE_PATH_ = askdirectory().replace('/', '\\')
if ("Windows" in platform.system()):
	SEPARATOR_ = "\\"
	PIP_NAME_ = PIP_NAME_D_ = "pip.exe"
	PYTHON_NAME_ = PYTHON_NAME_D_ = "python.exe"
	OS_NAME_ = "Windows"
elif ("Linux" in platform.system()):
	SEPARATOR_ = "/"
	PIP_NAME_ = PIP_NAME_D_ = "pip"
	PYTHON_NAME_ = PYTHON_NAME_D_ = "python3"
	OS_NAME_ = "Linux"
else:
	SEPARATOR_ = "/"
	PIP_NAME_ = PIP_NAME_D_ = "pip3"
	PYTHON_NAME_ = PYTHON_NAME_D_ = "python3"
	OS_NAME_ = "Mac"

SPDX_LAST_MESSAGE = ''

def logProcess(mes):
	if (SPDX_LOG_MODE):
		print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]: {mes}")
		SPDX_LAST_MESSAGE = mes

def findDir(folderName: str, rootPath: str) -> str:
	for _dir in os.walk(rootPath):
		for folder in _dir[1]:
			if (folderName == folder):
				return _dir[0]
	return ''

def locatePipPython(project_dir, PIP_NAME, PYTHON_NAME):
	venvPath = findDir("env", project_dir)
	if (venvPath == ''):
		return (PIP_NAME, PYTHON_NAME)
	PIP_NAME = f"{venvPath}{SEPARATOR_}env{SEPARATOR_}Scripts{SEPARATOR_}" + PIP_NAME
	PYTHON_NAME = f"{venvPath}{SEPARATOR_}env{SEPARATOR_}Scripts{SEPARATOR_}" + PYTHON_NAME
	return (PIP_NAME, PYTHON_NAME)
	
PIP_NAME_, PYTHON_NAME_ = locatePipPython(SPDX_PROJECT_ROOT_PATH, PIP_NAME_, PYTHON_NAME_)

PP = pipParser(PIP_NAME_)

SPDX_CHECKSUMS_ALGS_NAMES = [
	"SHA1",
	"SHA256",
	"SHA512",
	"SHA3-256",
	"MD5"
]

sbom_file = {
	"spdxVersion": "SPDX-2.3",
	"dataLicense": "CC0-1.0",
	"SPDXID": "SPDXRef-DOCUMENT",
	"name": f"{SPDX_PROJECT_NAME}",
	"documentNamespace": f"https://spdx.org/spdxdocs/{SPDX_DOCUMENT_NAMESPACE}",
	"creationInfo": {
		"created": f"{SPDX_CREATION_DATE.strftime('%Y-%m-%dT%H:%M:%SZ')}",
		"creators" : [
			"Tool: SPDX-Generator-Diploma-0.2",
			"Organization: Gubkin Russian State University of Oil and Gas"
			]
		},
	"packages": [],
	"relationships": []
}

sbom_package_body = {
	"name": "",
	"SPDXID": "",
	"versionInfo": "",
	"supplier": "",
	"downloadLocation": "NOASSERTION",
	"licenseConcluded": "",
	"licenseDeclared": "",
	"licenseComments": "NOASSERTION",
	"copyrightText": "",
	"description": "",
	"checksums": []
}

checksums_package_body = {
	"algorithm": "",
	"checksumValue": ""
}

relationships_body = {
	"spdxElementId": "",
	"relatedSpdxElement": "",
	"relationshipType": ""
}

pip_package_body = {
	"Name": ["name"],
	"Version": ["versionInfo"],
	"Summary": ["description"],
	"License": [
		"licenseConcluded",
		"licenseDeclared"]
}

def parsePackageMetadata(packageName):
	None

def calculateHash(package_location, hash_handlers):
	if (os.path.isdir(package_location)):
		logProcess(f"calculating hash of folder: {package_location}")
		for _dir in os.walk(package_location):
			if (".vs" in _dir[0]):
				continue
			if (".git" in _dir[0]):
				continue
			if (f"{SEPARATOR_}env" in _dir[0]):
				continue
			for f in _dir[-1]:
				f_handler = open(f"{_dir[0]}{SEPARATOR_}{f}", 'rb')
				while True:
					data = f_handler.read(FILE_BUFFER_SIZE)
					if (not data):
						f_handler.close()
						break
					for handler in hash_handlers:
						handler.update(data)
	else:
		try:
			f_handler = open(package_location + '.py', 'rb')
		except:
			if ('searching in default python' in SPDX_LAST_MESSAGE):
				return -1
			logProcess(f"package {package_location.split(SEPARATOR_)[-1]} not found in virtual environment, searching in default python dir")
			return -1
		logProcess(f"calculating hash of file: {package_location.split(SEPARATOR_)[-1]}")
		while True:
			data = f_handler.read(FILE_BUFFER_SIZE)
			if (not data):
				f_handler.close()
				break
			for handler in hash_handlers:
				handler.update(data)
	return

def insertHashToPart(s_part, hash_handlers):
	s_part["checksums"] = []
	for i in range(len(hash_handlers)):
		checksum_part = checksums_package_body.copy()
		checksum_part["algorithm"] = SPDX_CHECKSUMS_ALGS_NAMES[i]
		checksum_part["checksumValue"] = hash_handlers[i].hexdigest()
		s_part["checksums"].append(checksum_part)

def projectSBOM(projectRootPath):
	sbom_part = sbom_package_body.copy()
	sbom_part["name"] = SPDX_PROJECT_NAME
	logProcess(f"processing spdx for project {SPDX_PROJECT_NAME}")
	sbom_part["versionInfo"] = "NOASSERTION"
	sbom_part["supplier"] = "NOASSERTION"
	sbom_part["downloadLocation"] = "NOASSERTION"
	license_text = "NOASSERTION"
	flag1 = True
	curr_dir_depth = None
	for i in os.walk(projectRootPath):
		curr_dir_depth = i
		break
	curr_dir_depth = curr_dir_depth[0].split(SEPARATOR_)
	for _dir in os.walk(projectRootPath):
		_dir_depth = _dir[0].split(SEPARATOR_)
		if ((len(_dir_depth) - len(curr_dir_depth)) > 1):
			break
		if (flag1):
			for f in _dir[-1]:
				if ("LICENSE" in f.upper()):
					f_holder = open(f"{_dir[0]}{SEPARATOR_}{f}")
					license_text = f_holder.read()
					f_holder.close()
					flag1 = False
					t4 = license_text.split('\n')[0].lstrip(' ').rstrip(' ')
					logProcess(f"found license for project: {t4}")
					break
	sbom_part["licenseConcluded"] = license_text.split('\n')[0].lstrip(' ').rstrip(' ')
	sbom_part["licenseDeclared"] = sbom_part["licenseConcluded"]
	sbom_part["copyrightText"] = license_text
	author_text = "NOASSERTION"
	flag1 = True
	for _dir in os.walk(projectRootPath):
		_dir_depth = _dir[0].split(SEPARATOR_)
		if ((len(_dir_depth) - len(curr_dir_depth)) > 1):
			break
		if (flag1):
			for f in _dir[-1]:
				if ("AUTHOR" in f.upper()):
					f_holder = open(f"{_dir[0]}{SEPARATOR_}{f}")
					author_text = f_holder.readlines()
					f_holder.close()
					flag1 = False
					break
	supplier_type = "NOASSERTION"
	author_name = "NOASSERTION"
	author_email = "NOASSERTION"
	for line in author_text:
		if ("@" in line):
			line = line.lstrip(' ').rstrip('\n').rstrip(' ')
			t1_arr = line.split(' ')
			for i in range(len(t1_arr)):
				if ("@" in t1_arr[i]):
					logProcess(f"found author email: {t1_arr[i]}")
					author_email = t1_arr[i]
					if ((len(t1_arr) > 1) and (author_name == "NOASSERTION")):
						t1_arr.remove(author_email)
						author_name = " ".join(t1_arr)
						logProcess(f"found author name: {author_name}")
						supplier_type = "Person"
					break
		if ((("Inc." in line) or ("Co." in line)) and (supplier_type == "NOASSERTION")):
			supplier_type = "Corporation"
			if ("Inc." in line):
				author_name = line.split("Inc.")[0].lstrip(' ').rstrip(' ')
				logProcess(f"found author name: {author_name}")
			else:
				author_name = line.split("Co.")[0].lstrip(' ').rstrip(' ')
				logProcess(f"found author name: {author_name}")
	sbom_part["supplier"] = f"{supplier_type}: {author_name} ({author_email})"
	sbom_part["description"] = "NOASSERTION"

	hash_handlers = [
	hashlib.sha1(),
	hashlib.sha256(),
	hashlib.sha512(),
	hashlib.sha3_256(),
	hashlib.md5()
	]
	calculateHash(projectRootPath, hash_handlers)
	insertHashToPart(sbom_part, hash_handlers)
	sbom_part["SPDXID"] = f"SPDXRef-Package-{hashlib.sha1(f'{SPDX_PROJECT_NAME}-{hash_handlers[0].hexdigest()}'.encode()).hexdigest()[:16]}"
	sbom_file["packages"].append(sbom_part)
	return sbom_part["SPDXID"]

def fileSBOM(filepath):
	sbom_part = sbom_package_body.copy()
	filename = filepath.split(SEPARATOR_)[-1]
	f_handler = open(filepath, 'rb')
	f_data = f_handler.read()
	f_handler.close()
	sbom_part["SPDXID"] = f"SPDXRef-File-{hashlib.sha1(f'{filename}-{hashlib.sha1(f_data).hexdigest()}'.encode()).hexdigest()[:16]}"
	t1 = sbom_part["SPDXID"]
	logProcess(f"processing file {t1}")
	sbom_part["name"] = filename
	sbom_part["versionInfo"] = sbom_file["packages"][0]["versionInfo"]
	sbom_part["supplier"] = sbom_file["packages"][0]["supplier"]
	sbom_part["downloadLocation"] = sbom_file["packages"][0]["downloadLocation"]
	sbom_part["licenseConcluded"] = sbom_file["packages"][0]["licenseConcluded"]
	sbom_part["licenseDeclared"] = sbom_file["packages"][0]["licenseDeclared"]
	sbom_part["copyrightText"] = sbom_file["packages"][0]["copyrightText"]
	sbom_part["description"] = sbom_file["packages"][0]["description"]
	hash_handlers = [
	hashlib.sha1(),
	hashlib.sha256(),
	hashlib.sha512(),
	hashlib.sha3_256(),
	hashlib.md5()
	]
	calculateHash(filepath[:-3], hash_handlers)
	insertHashToPart(sbom_part, hash_handlers)
	sbom_file["packages"].append(sbom_part)
	return sbom_part["SPDXID"]

def parseDefaultPackage(package_name):
	logProcess(f"creating SBOM part for {package_name}")
	sbom_part = sbom_package_body.copy()
	package_version = os.popen(f'{PYTHON_NAME_} -V').read().split(' ')[-1][:-1]
	sbom_part["name"] = package_name
	sbom_part["SPDXID"] = f"SPDXRef-Package-{hashlib.sha1(f'{package_name}-{package_version}'.encode()).hexdigest()[:16]}"
	t1 = sbom_part["SPDXID"]
	logProcess(f"SPDXID of SBOM part for {package_name} is {t1}")
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
	if (package_name == 'sys'):
		insertHashToPart(sbom_part, hash_handlers)
		sbom_file["packages"].append(sbom_part)
		return sbom_file["SPDXID"]
	'''
	#crossplatform block
	package_location = os.popen(f'{PYTHON_NAME_} -c "import os, sys; print(os.path.dirname(sys.executable))"').read()[:-1] + f'{SEPARATOR_}Lib{SEPARATOR_}{package_name}'
	t_arr1 = package_location.split(SEPARATOR_)
	if (("bin" in t_arr1) and (OS_NAME_ != "Windows")):
		t_arr1.remove("bin")
		t_arr1.insert(len(t_arr1) - 1, f"python{'.'.join(package_version.split('.')[0:-1])}")
		package_location = f"{SEPARATOR_}".join(t_arr1)
	'''
	package_location = os.popen(f'{PYTHON_NAME_} -c "import os, sys; print(os.path.dirname(sys.executable))"').read()[:-1]
	t1_arr = package_location.split(SEPARATOR_)
	if (t1_arr[-1].lower() == 'scripts'):
		t1_arr.remove('Scripts')
		t1_arr.append('Lib')
		t1_arr.append(package_name)
		package_location = f"{SEPARATOR_}".join(t1_arr)
	elif ("python" in t1_arr[-1].lower()):
		t1_arr.append('Lib')
		t1_arr.append(package_name)
		package_location = f"{SEPARATOR_}".join(t1_arr)

	if (calculateHash(package_location, hash_handlers) == -1):
		package_location = os.popen(f'{PYTHON_NAME_D_} -c "import os, sys; print(os.path.dirname(sys.executable))"').read()[:-1]
		t1_arr = package_location.split(SEPARATOR_)
		if (t1_arr[-1].lower() == 'scripts'):		
			t1_arr.remove('Scripts')
			t1_arr.append('Lib')
			t1_arr.append(package_name)
			package_location = f"{SEPARATOR_}".join(t1_arr)
		elif ("python" in t1_arr[-1].lower()):
			t1_arr.append('Lib')
			t1_arr.append(package_name)
			package_location = f"{SEPARATOR_}".join(t1_arr)
		if (calculateHash(package_location, hash_handlers) == -1):
			logProcess(f"cannot locate {package_name}, inserting default checksum")

	insertHashToPart(sbom_part, hash_handlers)
	sbom_file["packages"].append(sbom_part)
	return sbom_part["SPDXID"]

def emptyPackage(package_name):
	logProcess(f"creating SBOM part for {package_name}")
	sbom_part = sbom_package_body.copy()
	sbom_part["name"] = package_name
	sbom_part["versionInfo"] = "NOASSERTION"
	sbom_part["supplier"] = "NOASSERTION"
	sbom_part["downloadLocation"] = "NOASSERTION"
	sbom_part["licenseConcluded"] = "NOASSERTION"
	sbom_part["licenseDeclared"] = "NOASSERTION"
	sbom_part["copyrightText"] = "NOASSERTION"
	sbom_part["description"] = "NOASSERTION"

	hash_handlers = [
	hashlib.sha1(),
	hashlib.sha256(),
	hashlib.sha512(),
	hashlib.sha3_256(),
	hashlib.md5()
	]
	package_location = os.popen(f'{PYTHON_NAME_} -c "import os, sys; print(os.path.dirname(sys.executable))"').read()[:-1]
	t1_arr = package_location.split(SEPARATOR_)
	if (t1_arr[-1].lower() == 'scripts'):
		t1_arr.remove('Scripts')
		t1_arr.append('Lib')
		t1_arr.append('site-packages')
		t1_arr.append(package_name)
		package_location = f"{SEPARATOR_}".join(t1_arr)
	elif ("python" in t1_arr[-1].lower()):
		t1_arr.append('Lib')
		t1_arr.append('site-packages')
		t1_arr.append(package_name)
		package_location = f"{SEPARATOR_}".join(t1_arr)

	if (calculateHash(package_location, hash_handlers) == -1):
		package_location = os.popen(f'{PYTHON_NAME_D_} -c "import os, sys; print(os.path.dirname(sys.executable))"').read()[:-1]
		if (t1_arr[-1].lower() == 'scripts'):		
			t1_arr.remove('Scripts')
			t1_arr.append('Lib')
			t1_arr.append('site-packages')
			t1_arr.append(package_name)
			package_location = f"{SEPARATOR_}".join(t1_arr)
		elif ("python" in t1_arr[-1].lower()):
			t1_arr.append('Lib')
			t1_arr.append('site-packages')
			t1_arr.append(package_name)
			package_location = f"{SEPARATOR_}".join(t1_arr)
		if (calculateHash(package_location, hash_handlers) == -1):
			logProcess(f"cannot locate {package_name}, inserting default checksum")
	insertHashToPart(sbom_part, hash_handlers)
	sbom_part["SPDXID"] = f"SPDXRef-Package-{hashlib.sha1(f'{package_name}-{hash_handlers[0].hexdigest()}'.encode()).hexdigest()[:16]}"
	t1 = sbom_part["SPDXID"]
	logProcess(f"SPDXID of SBOM part for {package_name} is {t1}")
	sbom_file["packages"].append(sbom_part)
	return sbom_part["SPDXID"]

def parsePackage(package_name):
	logProcess(f"creating SBOM part for {package_name}")
	a = PP.getPackageInfo(package_name).split('\n')
	# a = os.popen(f'{PIP_NAME_} show {package_name}').read().split('\n')
	sbom_part = sbom_package_body.copy()
	package_author = ""
	package_author_email = ""
	package_location = ""
	if (len(a) == 1):
		return emptyPackage(package_name)

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
	t1 = sbom_part["SPDXID"]
	logProcess(f"SPDXID of SBOM part for {package_name} is {t1}")
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
	package_location += f"{SEPARATOR_}{package_name}"
	package_dist_info_location = package_location + f"-{package_version}.dist-info{SEPARATOR_}"
	license_file_location = ""
	for _dir in os.walk(package_dist_info_location):
		for f in _dir[-1]:
			if ("LICENSE" in f.upper()):
				license_file_location = f"{_dir[0]}{SEPARATOR_}{f}"
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
	calculateHash(package_location, hash_handlers)
	insertHashToPart(sbom_part, hash_handlers)
	sbom_file["packages"].append(sbom_part)
	return sbom_part["SPDXID"]

def listAllPyFiles(root_folder):
	py_files = []
	for _dir in (os.walk(root_folder)):
		if ("env" in _dir[0]):
			continue
		for f in _dir[-1]:
			if (f[-3:] == ".py"):
				logProcess(f"found file {f}")
				py_files.append(f"{_dir[0]}{SEPARATOR_}{f}")
	return py_files

def parseModules(file_path):
	logProcess(f"parsing modules from {file_path}")
	modules = set()
	f = open(file_path)
	data = f.readlines()
	f.close()
	for line in data:
		line = line.rstrip('\n')
		if (("from " in line) and ("#" not in line) and ("import " in line)):
			mod_name = line.lstrip('from').lstrip(' ').split(' ')[0]
			logProcess(f"found module: {mod_name}")
			modules.add(mod_name)
			continue
		if (("import " in line) and ("#" not in line)):
			if (',' in line):
				t1 = line.split(',')
				t1[0] = t1[0].lstrip('import').lstrip(' ')
				t1[-1] = t1[-1].lstrip(' ').split(' ')[0]
				for i in range(len(t1)):
					mod_name = t1[i].lstrip(' ').rstrip(' ')
					logProcess(f"processing module: {mod_name}")
					modules.add(mod_name)
			else:
				mod_name = line.lstrip('import').lstrip(' ').split(' ')[0]
				logProcess(f"found module: {mod_name}")
				modules.add(mod_name)
	return modules

def isDefaultModule(module_name, PIP_NAME):
	a = PP.getPackageInfo(module_name)
	# a = os.popen(f'{PIP_NAME_} show {module_name}').read()
	if (a == ''):
		if (len(PIP_NAME) > 4):
			if ((os.path.isdir(f"{findDir('site-packages', SPDX_PROJECT_ROOT_PATH)}{SEPARATOR_}site-packages{SEPARATOR_}{module_name}")) or
				(os.path.isfile(f"{findDir('site-packages', SPDX_PROJECT_ROOT_PATH)}{SEPARATOR_}site-packages{SEPARATOR_}{module_name}"))):
				logProcess(f"module: {module_name} does not have dist-info but found in site-packages folder")
				return 0
		logProcess(f"module: {module_name} is built-in module")
		return 1
	logProcess(f"module: {module_name} is found")
	return 0

SPDX_PROJECT_SPDXID = projectSBOM(SPDX_PROJECT_ROOT_PATH)
JSON_DUMP_FILE_NAME_ = f"{SEPARATOR_}{SPDX_PROJECT_SPDXID}.json"
JSON_DUMP_FILE_PATH_ += JSON_DUMP_FILE_NAME_

SPDX_PY_FILES_PATHS = listAllPyFiles(SPDX_PROJECT_ROOT_PATH)
SPDX_PROJECT_TREENODE = treeNode(SPDX_PROJECT_ROOT_PATH)
SPDX_PROJECT_TREENODE.dependenciesFiles = SPDX_PY_FILES_PATHS.copy()
SPDX_PROJECT_TREENODE.SPDXID = SPDX_PROJECT_SPDXID
SPDX_TREENODE_CLASSES = {
	SPDX_PROJECT_ROOT_PATH: SPDX_PROJECT_TREENODE
	}

SPDX_PYTHON_MODULES = set()
SPDX_PYTHON_DEFAULT_MODULES = set()

for f in SPDX_PY_FILES_PATHS:
	logProcess(f"processing {f}")
	file_SPDXID = fileSBOM(f)
	if (SPDX_TREENODE_CLASSES.get(f) == None): SPDX_TREENODE_CLASSES[f] = treeNode(f)
	SPDX_TREENODE_CLASSES[f].SPDXID = file_SPDXID
	SPDX_TREENODE_CLASSES[SPDX_PROJECT_ROOT_PATH].dependenciesFiles_TN.append(SPDX_TREENODE_CLASSES[f])
	dependencies = list(parseModules(f))	# .split('.')[0]
	# SEP = ""
	# if ('/' in f): SEP = '/'
	# else: SEP = '\\'
	root_f = f"{SEPARATOR_}".join(f.split(SEPARATOR_)[0:-1]) + SEPARATOR_
	for modl in dependencies:
		logProcess(f"processing module: {modl}")
		c_root_f = f"{root_f}{SEPARATOR_}{modl.replace('.', SEPARATOR_)}.py"
		if (os.path.isfile(c_root_f)):
			if (SPDX_TREENODE_CLASSES.get(c_root_f) == None): SPDX_TREENODE_CLASSES[c_root_f] = treeNode(c_root_f)
			SPDX_TREENODE_CLASSES[f].dependenciesFiles_TN.append(SPDX_TREENODE_CLASSES[c_root_f])
		else:
			modl_base = modl.split('.')[0]
			if (SPDX_TREENODE_CLASSES.get(modl_base) == None): SPDX_TREENODE_CLASSES[modl_base] = treeNode(moduleName=modl_base)
			SPDX_TREENODE_CLASSES[f].dependenciesModules_TN.add(SPDX_TREENODE_CLASSES[modl_base])
			if (isDefaultModule(modl_base, PIP_NAME_)):
				SPDX_PYTHON_DEFAULT_MODULES.add(modl_base)
			else:
				SPDX_PYTHON_MODULES.add(modl_base)

SPDX_PROCESSED_MODULES = {}

def getChildrenModules(moduleName):
	modules = []
	if (SPDX_PROCESSED_MODULES.get(moduleName) != None):
		logProcess(f"found cached children for {moduleName}")
		return SPDX_PROCESSED_MODULES[moduleName]
	logProcess(f"finding children for {moduleName}")
	a = PP.getPackageInfo(moduleName).split('\n')
	# a = os.popen(f'{PIP_NAME_} show {moduleName}').read().split('\n')
	for item in a:
		if ("Requires" in item):
			t1 = item.rstrip('\n').rstrip(' ').split(':', 1)[-1]
			modules = t1.lstrip(' ').split(', ')
			break
	modules_set = set()
	if (SPDX_PROCESSED_MODULES.get(moduleName) == None):
		if ((modules[0] == '') if (len(modules) > 0) else True):
			modules_set = set()
		else:
			modules_set = set(modules)
		SPDX_PROCESSED_MODULES[moduleName] = modules_set
	if ((modules[0] == '') if (len(modules) > 0) else True):
		logProcess("found 0 children")
		return set()
	logProcess(f"found: {modules} {len(modules)} children")
	for modl in modules:
		t2 = getChildrenModules(modl)
		for i in t2:
			modules_set.add(i)
	return modules_set

temp_modules_set = set()
print(SPDX_PYTHON_MODULES)
for modl in SPDX_PYTHON_MODULES:
	t1 = getChildrenModules(modl)
	for modl2 in t1:
		if (SPDX_TREENODE_CLASSES.get(modl) == None): SPDX_TREENODE_CLASSES[modl] = treeNode(moduleName=modl)
		if (SPDX_TREENODE_CLASSES.get(modl2) == None): SPDX_TREENODE_CLASSES[modl2] = treeNode(moduleName=modl2)
		SPDX_TREENODE_CLASSES[modl].dependenciesModules_TN.add(SPDX_TREENODE_CLASSES[modl2])
		if (isDefaultModule(modl2, PIP_NAME_)):
			SPDX_PYTHON_DEFAULT_MODULES.add(modl2)
		else:
			temp_modules_set.add(modl2)

for modl in temp_modules_set:
	SPDX_PYTHON_MODULES.add(modl)

print(SPDX_PYTHON_MODULES)

for modl in SPDX_PYTHON_MODULES:
	SPDX_TREENODE_CLASSES[modl].SPDXID = parsePackage(modl)

for modl in SPDX_PYTHON_DEFAULT_MODULES:
	SPDX_TREENODE_CLASSES[modl].SPDXID = parseDefaultPackage(modl)

for part in sbom_file["packages"]:
	part["licenseConcluded"] = "NOASSERTION"
	part["licenseDeclared"] = "NOASSERTION"

rs_doc_part = relationships_body.copy()
rs_doc_part["spdxElementId"] = sbom_file["SPDXID"]
rs_doc_part["relatedSpdxElement"] = SPDX_PROJECT_TREENODE.SPDXID
rs_doc_part["relationshipType"] = "DESCRIBES"
sbom_file["relationships"].append(rs_doc_part)

def addRelationshipsForPackage(packageTN : treeNode):
	if (packageTN.SPDXID == ''):
		return
	logProcess(f"building relationships for {packageTN.SPDXID}: {packageTN.moduleName}")
	for pack in packageTN.dependenciesFiles_TN:
		logProcess(f"attaching {pack.SPDXID} to {packageTN.SPDXID}")
		rs_part = relationships_body.copy()
		rs_part["spdxElementId"] = packageTN.SPDXID
		rs_part["relatedSpdxElement"] = pack.SPDXID
		rs_part["relationshipType"] = "DEPENDS_ON"
		sbom_file["relationships"].append(rs_part)
	for pack in packageTN.dependenciesModules_TN:
		logProcess(f"attaching {pack.SPDXID} to {packageTN.SPDXID}")
		rs_part = relationships_body.copy()
		rs_part["spdxElementId"] = packageTN.SPDXID
		rs_part["relatedSpdxElement"] = pack.SPDXID
		rs_part["relationshipType"] = "DEPENDS_ON"
		sbom_file["relationships"].append(rs_part)
	return

for pack in SPDX_TREENODE_CLASSES:
	addRelationshipsForPackage(SPDX_TREENODE_CLASSES[pack])


'''
logic:
+1.	locate all .py files
+	build dict { filepath: class treeNode } (local files)
+2.	get dependencies (1. pip, 2. in files)
+	write all dependencies to classes
+3.	build relationships files tree (local files + default modules) from dict
+4.	get info about every file and add to sbom_file
+5.	get info about every module and add to sbom_file
+6.	get dependencies of all modules
7.	add relationships to sbom_file
'''

'''
+	default packages reaction
+	packages installed not via pip (check local directories)
+	check virtual environment pip
+	dependencies check (set of all modules)
+	multi-platform
	relationships
	cache for located modules
	check module without using 'pip show <moduleName>'
		deep packages searching (replace('-','_'), check RECORD file in dist-info)
'''

logProcess(f"Dumping SPDX into {JSON_DUMP_FILE_NAME_}")
f_handler_json = open(JSON_DUMP_FILE_PATH_, 'w')
json.dump(sbom_file, fp=f_handler_json, indent=4)
f_handler_json.close()
