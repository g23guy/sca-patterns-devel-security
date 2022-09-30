#!/usr/bin/python3
SVER = '1.0.9_dev1'
##############################################################################
# sapat-suma.py - Security Advisory Announcement Pattern Generator for SUMA
# Copyright (C) 2022 SUSE LLC
#
# Description:  Creates a python security advisory pattern from HTML SUMA pages
# Modified:     2022 Sep 30
#
##############################################################################
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#  Authors/Contributors:
#     Jason Record <jason.record@suse.com>
#
##############################################################################

import sys
import getopt
import os
import re
import datetime
import urllib.request, urllib.parse, urllib.error

AUTHOR = 'Jason Record <jason.record@suse.com>'
MD = {
	'url': '',
	'file': '',
	'name': '',
	'severity': '',
	'tag': '',
}
CNT = {
	'errors': 0,
	'skipped': 0,
	'success': 0,
	'patterns': 0
}

PATDIR = "/home/opt/chksecurity/patterns/"
FILE = {}
PACKAGES = {}
PACKAGE_ERRORS = 0
APLIST = {}
LTSS = 'False'
FAILURE = False
DISTROS = {}
DISPLAY = "{0:15} = {1}"
VERBOSE = True
QUIET = False
RCODE = 0

def title():
	print("\n##################################################")
	print("# SUMA Security Announcement Parser, v" + str(SVER))
	print("##################################################")

def createPattern(VERSION):
#	print "  >createPattern(" + str(VERSION) + ")"
	global PACKAGES
	PATTERN_ID = str(MD['name']).lower() + "_" + str(MD['tag']) + "_suma-" + str(VERSION) + ".py"
	PATTERN_ID = PATTERN_ID.replace(':', '_')
#	print "Creating pattern with " + str(len(PACKAGES)) + " packages: " + PATTERN_ID
	if( VERBOSE ):
		print(DISPLAY.format('Pattern', str(PATTERN_ID) + " (" +  str(len(PACKAGES)) + " packages)"))

	TODAY = datetime.date.today()
	# Build pattern file content
	CONTENT = "#!/usr/bin/python\n#\n"
	CONTENT += "# Title:       " + str(MD['severity']) +" SUMA Security Announcement for " + str(MD['name']).replace(':', '') + " " + str(MD['tag']) + "\n"
	if 'True' in LTSS:
		CONTENT += "# Description: Security fixes for SUSE Manager " + str(VERSION) + " LTSS\n"
	else:
		CONTENT += "# Description: Security fixes for SUSE Manager " + str(VERSION) + "\n"
	CONTENT += "# Source:      SUMA Security Announcement Parser v" + str(SVER) + "\n"
	CONTENT += "# Modified:    " + str(TODAY.strftime("%Y %b %d")) + "\n"
	CONTENT += "#\n##############################################################################\n"
	CONTENT += "# Copyright (C) " + str(TODAY.year) + " SUSE LLC\n"
	CONTENT += "##############################################################################\n#\n"
	CONTENT += "# This program is free software; you can redistribute it and/or modify\n"
	CONTENT += "# it under the terms of the GNU General Public License as published by\n"
	CONTENT += "# the Free Software Foundation; version 2 of the License.\n#\n"
	CONTENT += "# This program is distributed in the hope that it will be useful,\n"
	CONTENT += "# but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
	CONTENT += "# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
	CONTENT += "# GNU General Public License for more details.\n#\n"
	CONTENT += "# You should have received a copy of the GNU General Public License\n"
	CONTENT += "# along with this program; if not, see <http://www.gnu.org/licenses/>.\n#\n"
	CONTENT += "#  Authors/Contributors:\n#   " + AUTHOR + "\n#\n"
	CONTENT += "##############################################################################\n\n"
	CONTENT += "import os\n"
	CONTENT += "import Core\n"
	CONTENT += "import SUSE\n"
	CONTENT += "import suma\n\n"
	CONTENT += "META_CLASS = \"Security\"\n"
	CONTENT += "META_CATEGORY = \"SUMA\"\n"
	CONTENT += "META_COMPONENT = \"" + str(MD['name']) + "\"\n"
	CONTENT += "PATTERN_ID = os.path.basename(__file__)\n"
	CONTENT += "PRIMARY_LINK = \"META_LINK_Security\"\n"
	CONTENT += "OVERALL = Core.TEMP\n"
	CONTENT += "OVERALL_INFO = \"NOT SET\"\n"
	CONTENT += "OTHER_LINKS = \"META_LINK_Security=" + str(MD['url']) + "\"\n"
	CONTENT += "Core.init(META_CLASS, META_CATEGORY, META_COMPONENT, PATTERN_ID, PRIMARY_LINK, OVERALL, OVERALL_INFO, OTHER_LINKS)\n\n"
	CONTENT += "LTSS = " + str(LTSS) + "\n"
	CONTENT += "NAME = '" + MD['name'] + "'\n"
	CONTENT += "MAIN = ''\n"
	CONTENT += "SEVERITY = '" + MD['severity'] + "'\n"
	CONTENT += "TAG = '" + MD['tag'] + "'\n"
	CONTENT += "PACKAGES = {}\n"
	CONTENT += "SUMA = suma.getSumaInfo()\n\n"
	if( len(PACKAGES) == 0 ):
		CONTENT += "ERROR_FixEmptyPackageList\n"
# Force error for now
	CONTENT += "ERROR_AbortSUMAPatterns\n"
	CONTENT += "if ( SUMA['Installed'] ):\n"
	CONTENT += "\tif ( SUMA['Version'] == '" + str(VERSION) + "' ):\n"
	CONTENT += "\t\tPACKAGES = {\n"

	for KEY in sorted(PACKAGES):
		CONTENT += "\t\t\t'" + str(KEY) + "': '" + str(PACKAGES[KEY]) + "',\n"

	CONTENT += "\t\t}\n"
	CONTENT += "\t\tSUSE.securityAnnouncementPackageCheck(NAME, MAIN, LTSS, SEVERITY, TAG, PACKAGES)\n"
	CONTENT += "\telse:\n"
	CONTENT += "\t\tCore.updateStatus(Core.ERROR, \"ERROR: \" + NAME + \" Security Announcement: Outside the SUMA version scope\")\n"
	CONTENT += "else:\n"
	CONTENT += "\tCore.updateStatus(Core.ERROR, \"ERROR: \" + NAME + \" Security Announcement: SUMA Not Installed\")\n"
	CONTENT += "Core.printPatternResults()\n\n"


	# Write the content to disk
	try:
		PATFILE = PATDIR + PATTERN_ID
		FILE_OPEN = open(PATFILE, "w")
		FILE_OPEN.write(CONTENT)
		FILE_OPEN.close()
		os.chmod(PATFILE, 0o755)
	except Exception as error:
		print(" ERROR: Cannot create " + str(PATFILE) + ": " + str(error))
#	print "  <createPattern: " + str(FILE_OPEN)

def getSecurityAnnouncement(FILE):
#	print "  >getSecurityAnnouncement(" + str(FILE) + ")"
	global MD
	MD['file'] = MD['url'].split("/")[-1]
	FILE_OPEN = MD['file']
	MD['url'] = MD['url'].replace("//" + FILE_OPEN, "/" + FILE_OPEN)
	if( VERBOSE ):
		print(DISPLAY.format('Downloading URL', str(MD['url'])))
	try:
		urllib.request.urlretrieve(MD['url'], FILE_OPEN)
	except Exception as error:
		print(" ERROR: Cannot download " + str(MD['url']) + ": " + str(error))
		sys.exit()

	if( VERBOSE ):
		print(DISPLAY.format('Loading File', str(FILE_OPEN)))
	try:
		FILE_OPENED = open(FILE_OPEN)
	except Exception as error:
		print(" ERROR: Cannot open " + str(FILE_OPEN) + ": " + str(error))
		sys.exit()

	I = 0
	INVALID = re.compile(r'>Object not found!<', re.IGNORECASE)
	for LINE in FILE_OPENED:
		LINE = LINE.strip("\n")
		if INVALID.search(LINE):
			FILE = {}
			print(" ERROR: Invalid Security Announcement File: " + str(MD['file']))
			FILE_OPENED.close()
			sys.exit()
		FILE[I] = LINE
		I += 1
	FILE_OPENED.close()
#	print "  <getSecurityAnnouncement"

def getMetaData(MD):
#	print "  >getMetaData(" + str(MD) + ")"
	for LINE in FILE:
		TEXT = FILE[LINE].strip().replace('<br>', '') # clean up line
		if TEXT.startswith("SUSE Security Update: "):
			if "java" in TEXT.lower():
				MD['name'] = "Java"
			else:
				MD['name'] = re.sub('[,]', '', TEXT.split()[-1])
		elif TEXT.startswith("Announcement ID:"):
			MD['tag'] = TEXT.split()[-1]
		elif TEXT.startswith("Rating:"):
			MD['severity'] = TEXT.split()[-1].title()
	if( VERBOSE ):
		print(DISPLAY.format('Name', str(MD['name'])))
		print(DISPLAY.format('Tag', str(MD['tag'])))
		print(DISPLAY.format('Severity', str(MD['severity'])))
#	print "  <getMetaData"

def getAffectedProducts(APLIST):
#	print "  >getAffectedProducts(" + str(APLIST) + ")"
	AffectedProductList = re.compile("^Affected Products:", re.IGNORECASE)
	GetDistro = re.compile("SUSE Manager")
	STATE = False
	I = 0
	for LINE in FILE:
		if( STATE ):
			if FILE[LINE].startswith("_____"):
				STATE = False
				break
			else:
				if GetDistro.search(FILE[LINE]):
					if "client" not in FILE[LINE].lower():
						TMP_LIST = FILE[LINE].strip().replace('<br>', '').split()
						# currently the only possibile strings in the url are 
						# SUSE Manager 1.2, SUSE Manager 1.7, SUSE Manager Server and SUSE Manager Proxy. 
						# So only the first three are significant
						del TMP_LIST[3:]
						APLIST[I] = " ".join(TMP_LIST)
						I += 1
		elif AffectedProductList.search(FILE[LINE]):
			STATE = True
	if( VERBOSE ):
		print(DISPLAY.format('Products', str(len(APLIST))))
#	print "  <getAffectedProducts: APLIST=" + str(APLIST)

def getVersion(PRODUCT):
#	print "  >getVersion(" + str(PRODUCT) + ")"
	TMP = PRODUCT.split()
	for TEXT in TMP:
#		print " TEXT = " + str(TEXT)
		if "1." in TEXT:
			VER = TEXT
		elif "server" in TEXT.lower():
			VER = "2.1"
		elif "proxy" in TEXT.lower():
			VER = "2.1"
		else:
			VER = TMP[-1]
#	print "  <getVersion: " + str(VER)
	return VER
	
def getPackages(INDEX):
#	print "  >getPackages(" + str(INDEX) + ")"
	global PACKAGES
	global PACKAGE_ERRORS
	IN_PACKAGE_LIST = False
	PROD_LIST = False
	PL = re.compile("^-.*" + str(APLIST[INDEX]))
	for LINE in FILE:
		TEXT = FILE[LINE].strip().replace('<br>', '')
		if( IN_PACKAGE_LIST ):
			if TEXT.startswith("References:"):
				IN_PACKAGE_LIST = False
				PROD_LIST = False
				break
			elif( PROD_LIST ):
				if TEXT.startswith('-'):
					if not PL.search(TEXT):
#						print "  Using " + str(APLIST[INDEX])
#						print "  Found " + str(TEXT)
						PROD_LIST = False
				elif( len(TEXT) > 0 ):
					if TEXT.endswith('):'):
						continue
					elif TEXT.endswith(']:'):
						continue
					else:
#						print "\n"
#						print "TEXT = " + str(TEXT)
						PARTS = TEXT.split('-')
						VERSION = PARTS[-2] + '-' + PARTS[-1]
						del PARTS[-1]
						del PARTS[-1]
						NAME = '-'.join(PARTS)
#						print "NAME|VERSION = " + str(NAME) + "|" + str(VERSION)
#						print PACKAGES
						if NAME in PACKAGES:
							if( PACKAGES[NAME] != VERSION ):
								PACKAGE_ERRORS += 1
#								print " ERROR: Package version conflict for " + str(NAME) + ": " + str(PACKAGES[NAME]) + " and " + str(VERSION)
								PACKAGES[NAME] = VERSION
						else:
							PACKAGES[NAME] = VERSION
			elif PL.search(TEXT):
				PROD_LIST = True
#				print "  Found product list " + str(TEXT)
		elif TEXT.startswith("Package List:"):
			IN_PACKAGE_LIST = True
#			print " Found package list"

#	print "   Package List: " + str(len(PACKAGES))
#	for KEY in PACKAGES:
#		print "    '" + str(KEY) + "': '" + str(PACKAGES[KEY]) + "',"
#	print "  <getPackages: PACKAGE_ERRORS=" + str(PACKAGE_ERRORS)

def cleanUp():
	global MD
	try:
		os.unlink(MD['file'])
	except Exception as error:
		print(" ERROR: Cannot delete " + str(MD['file']) + ": " + str(error))

def showSummary():
	global CNT
	print((" Patterns: " + str(CNT['patterns']) + ", Success: " + str(CNT['success']) + ", Skipped: " + str(CNT['skipped']) + ", Errors: " + str(CNT['errors'])))

###########################################################################
# MAIN
###########################################################################
if( len(sys.argv[1:]) > 0 ):
	try:
		options, remainder = getopt.getopt(sys.argv[1:], "hqs", ["help", "quiet", "summary"])
#		print(options)
#		print(remainder)
	except getopt.GetoptError as err:
		# print help information and exit:
		title()
		usage()
		print(("ERROR: " + str(err))) # will print something like "option -b not recognized"
		print()
		sys.exit(2)
else:
	title()
	usage()
	print("ERROR: Missing Advisory URL")
	sys.exit(1)

for opt, arg in options:
#	print(opt)
#	print(arg)
	if opt in ("-h", "--help"):
		title()
		usage()
		sys.exit(0)
	elif opt in ("-q", "--quiet"):
		QUIET = True
		VERBOSE = False
	elif opt in ("-s", "--summary"):
		QUIET = False
		VERBOSE = False

if( remainder ):
	MD['url'] = remainder[0]
else:
	title()
	usage()
	print("ERROR: Missing Advisory URL")
	sys.exit(1)

if VERBOSE:
    title()
getSecurityAnnouncement(FILE)
getMetaData(MD)
getAffectedProducts(APLIST)
PACKAGE_ERRORS = 0
for I in APLIST:
	CNT['patterns'] += 1
#	print "\n  * Start main loop: " + str(APLIST[I])
	if "suse manager" in APLIST[I].lower():
		if APLIST[I].endswith("LTSS"):
			LTSS = 'True'
		else:
			LTSS = 'False'
		PACKAGES = {}
		getPackages(I)
		if( PACKAGE_ERRORS > 0 ):
			PACKAGES = {}
			FAILURE = True
			print(" ERROR: Detected " + str(PACKAGE_ERRORS) + " package version errors for " + str(APLIST[I]))
		createPattern(getVersion(APLIST[I]))
cleanUp()
if( FAILURE ):
	CNT['errors'] += 1
	if( VERBOSE ):
		print(DISPLAY.format('Status', '** FAILURE **'))
	RCODE = 1
else:
	CNT['success'] += 1
	if( VERBOSE ):
		print(DISPLAY.format('Status', 'Success'))
if( not VERBOSE ):
	if( not QUIET ):
		showSummary()
sys.exit(RCODE)

