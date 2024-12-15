import os
class pipParser:
	def __init__(self, PIP_NAME):
		self.PIP_NAME = PIP_NAME
		self.cache = {}

	def getPackageInfo(self, packageName):
		if (self.cache.get(packageName) == None):
			a = os.popen(f'{self.PIP_NAME} show {packageName}').read()
			self.cache[packageName] = a
			return a
		else:
			return self.cache[packageName]

