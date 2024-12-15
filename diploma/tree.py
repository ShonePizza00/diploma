class treeNode:
	def __init__(self, filePath='', moduleName=''):
		self.filePath = filePath
		self.moduleName = moduleName
		self.SPDXID = ""
		#self.dependenciesFiles = []
		self.dependenciesFiles_TN = []		# treeNode
		#self.dependenciesModules = set()
		self.dependenciesModules_TN = set()	# treeNode

