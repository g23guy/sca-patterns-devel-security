#!/usr/bin/python3
SVER = '1.6.4'
##############################################################################
# sapat.py - Security Advisory Announcement Pattern Generator
# Copyright (C) 2022 SUSE LLC
#
# Description:  Creates a python security advisory pattern from HTML page
# Modified:     2022 Mar 10
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
import os
import re
import getopt
import datetime
import urllib.request, urllib.parse, urllib.error

AUTHOR = 'Jason Record <jason.record@suse.com>'
MD = {
	'url': '',
	'file': '',
	'name': 'Update',
	'severity': '',
	'tag': '',
	'rt_kernel': False,
	'kgraft_kernel': False
}
CNT = {
	'errors': 0,
	'skipped': 0,
	'duplicate': 0,
	'success': 0,
	'patterns': 0
}

PATDIR = '/home/opt/chksecurity/patterns/'
FILE = {}
PACKAGES = {}
PACKAGE_ERRORS = 0
APLIST = []
FAILURE = False
ERR_PKG_VERSION = False
ERR_PKG_EMPTY = False
DISTRO = ''
DISPLAY = "{0:15} = {1}"
VERBOSE = True
QUIET = False
RCODE = 0

def title():
	print("\n##################################################")
	print("# Security Announcement Parser, v" + str(SVER))
	print("##################################################")

def createPattern():
	global PACKAGES
	global DISTRO
	global CNT
	(DIST, PATCH, LTSS_STR) = DISTRO.split('.')
	if( len(LTSS_STR) > 0 ):
		ADD_LTSS_STR="." + LTSS_STR
	else:
		ADD_LTSS_STR=''
	PATTERN_ID = str(MD['name']).lower() + "_" + str(MD['tag']) + "_" + str(DIST) + "." + str(PATCH) + ADD_LTSS_STR + ".py"
	PATTERN_ID = PATTERN_ID.replace(':', '_')
#	print "Creating pattern with " + str(len(PACKAGES)) + " packages: " + PATTERN_ID
	if( VERBOSE ):
		print(DISPLAY.format('Pattern', str(PATTERN_ID) + " (" +  str(len(PACKAGES)) + " packages)"))

	TODAY = datetime.date.today()
	# Build pattern file content
	CONTENT = "#!/usr/bin/python3\n#\n"
	CONTENT += "# Title:       " + str(MD['severity']) +" Security Announcement for " + str(MD['name']).replace(':', '') + " " + str(MD['tag']) + "\n"
	if 'ltss' in LTSS_STR:
		if( MD['rt_kernel'] ):
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise Real Time Kernel " + str(DIST) + " SP" + str(PATCH) + " LTSS\n"
		elif( MD['kgraft_kernel'] ): 
			CONTENT += "# Description: Security fixes for SUSE Linux Kernel Live Patch " + str(DIST) + " SP" + str(PATCH) + " LTSS\n"
		else:
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise " + str(DIST) + " SP" + str(PATCH) + " LTSS\n"
	else:
		if( MD['rt_kernel'] ):
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise Real Time Kernel " + str(DIST) + " SP" + str(PATCH) + "\n"
		elif( MD['kgraft_kernel'] ): 
			CONTENT += "# Description: Security fixes for SUSE Linux Kernel Live Patch " + str(DIST) + " SP" + str(PATCH) + "\n"
		else:
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise " + str(DIST) + " SP" + str(PATCH) + "\n"
	CONTENT += "# Source:      Security Announcement Parser v" + str(SVER) + "\n"
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
	CONTENT += "import SUSE\n\n"
	CONTENT += "META_CLASS = \"Security\"\n"
	CONTENT += "META_CATEGORY = \"SLE\"\n"
	CONTENT += "META_COMPONENT = \"" + str(MD['name']) + "\"\n"
	CONTENT += "PATTERN_ID = os.path.basename(__file__)\n"
	CONTENT += "PRIMARY_LINK = \"META_LINK_Security\"\n"
	CONTENT += "OVERALL = Core.TEMP\n"
	CONTENT += "OVERALL_INFO = \"NOT SET\"\n"
	CONTENT += "OTHER_LINKS = \"META_LINK_Security=" + str(MD['url']) + "\"\n"
	CONTENT += "Core.init(META_CLASS, META_CATEGORY, META_COMPONENT, PATTERN_ID, PRIMARY_LINK, OVERALL, OVERALL_INFO, OTHER_LINKS)\n\n"
	if 'ltss' in LTSS_STR:
		CONTENT += "LTSS = True\n"
	else:
		CONTENT += "LTSS = False\n"
	CONTENT += "NAME = '" + MD['name'] + "'\n"
	CONTENT += "MAIN = ''\n"
	CONTENT += "SEVERITY = '" + MD['severity'] + "'\n"
	CONTENT += "TAG = '" + MD['tag'] + "'\n"
	CONTENT += "PACKAGES = {}\n"
	CONTENT += "SERVER = SUSE.getHostInfo()\n\n"
	if( ERR_PKG_VERSION ):
		CONTENT += "ERROR_FixPackageVersionErrors\n"
	elif( ERR_PKG_EMPTY ):
		CONTENT += "ERROR_FixEmptyPackageList\n"
	CONTENT += "if ( SERVER['DistroVersion'] == " + str(DIST) + "):\n"
	CONTENT += "\tif ( SERVER['DistroPatchLevel'] == " +  str(PATCH) + " ):\n"
	CONTENT += "\t\tPACKAGES = {\n"

	for KEY in sorted(PACKAGES):
		CONTENT += "\t\t\t'" + str(KEY) + "': '" + str(PACKAGES[KEY]) + "',\n"

	CONTENT += "\t\t}\n"
	CONTENT += "\t\tSUSE.securityAnnouncementPackageCheck(NAME, MAIN, LTSS, SEVERITY, TAG, PACKAGES)\n"
	CONTENT += "\telse:\n"
	CONTENT += "\t\tCore.updateStatus(Core.ERROR, \"ERROR: \" + NAME + \" Security Announcement: Outside the service pack scope\")\n"
	CONTENT += "else:\n"
	CONTENT += "\tCore.updateStatus(Core.ERROR, \"ERROR: \" + NAME + \" Security Announcement: Outside the distribution scope\")\n"
	CONTENT += "Core.printPatternResults()\n\n"


	# Write the content to disk
	PATFILE = PATDIR + PATTERN_ID
	if( os.path.exists(PATFILE) ):
		CNT['duplicate'] += 1
		if( VERBOSE ):
			print(" ERROR: Pattern collision, duplicate " + PATFILE)
		cleanUp()
#		sys.exit(4)
	else:
		try:
			FILE_OPEN = open(PATFILE, "w")
			FILE_OPEN.write(CONTENT)
			FILE_OPEN.close()
			os.chmod(PATFILE, 0o755)
		except Exception as error:
			print(" ERROR: Cannot create " + str(PATFILE) + ": " + str(error))

def getSecurityAnnouncement(FILE):
	global MD
#	MD['url'] = sys.argv[1]
	MD['file'] = MD['url'].split("/")[-1]
	FILE_OPEN = MD['file']
	MD['url'] = MD['url'].replace("//" + FILE_OPEN, "/" + FILE_OPEN)
	if( VERBOSE ):
		print(DISPLAY.format('Downloading URL', str(MD['url'])))
	try:
		urllib.request.urlretrieve(MD['url'], FILE_OPEN)
	except Exception as error:
		if( VERBOSE ):
			print(" ERROR: Cannot download " + str(MD['url']) + ": " + str(error))
		sys.exit()

	if( VERBOSE ):
		print(DISPLAY.format('Loading File', str(FILE_OPEN)))
	try:
		FILE_OPENED = open(FILE_OPEN)
	except Exception as error:
		print(" ERROR: Cannot open " + str(FILE_OPEN) + ": " + str(error))
		cleanUp()
		sys.exit()

	I = 0
	INVALID = re.compile(r'>Object not found!<', re.IGNORECASE)
	for LINE in FILE_OPENED:
		LINE = LINE.strip("\n")
		if INVALID.search(LINE):
			FILE = {}
			print(" ERROR: Invalid Security Announcement File: " + str(MD['file']))
			FILE_OPENED.close()
			cleanUp()
			sys.exit()
		FILE[I] = LINE
		I += 1
	FILE_OPENED.close()

def getMetaData(MD):
	SUSE_RT = re.compile("SUSE Linux Enterprise Real Time", re.IGNORECASE)
	SUSE_KGRAFT = re.compile("Linux Kernel.*Live Patch", re.IGNORECASE)
	SUSE_DEFAULT = re.compile("SUSE Security Update:", re.IGNORECASE)
	for LINE in FILE:
		TEXT = FILE[LINE].strip().replace('<br>', '') # clean up line
		if SUSE_RT.search(TEXT):
			if( not MD['rt_kernel'] ):
				MD['rt_kernel'] = True
				MD['name'] = str(MD['name']) + "-rt"
		elif SUSE_KGRAFT.search(TEXT):
			MD['kgraft_kernel'] = True
			MD['name'] = "kgraft-patch"
		elif SUSE_DEFAULT.search(TEXT):
			if "java" in TEXT.lower():
				MD['name'] = "Java"
			elif "apache" in TEXT.lower():
				MD['name'] = "Apache"
			elif "kerberos" in TEXT.lower():
				MD['name'] = "Kerberos"
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

def getAffectedProducts(APLIST):
#	print("  >getAffectedProducts")
	AffectedProductList = re.compile("^Affected Products:", re.IGNORECASE)
	GetDistro = re.compile("SUSE Linux Enterprise Server [0-9]|SUSE Linux Enterprise Desktop [0-9]|SUSE Linux Enterprise Module for Basesystem", re.IGNORECASE)
	STATE = False
	for LINE in FILE:
		if( STATE ):
#			print "AP LINE: " + str(FILE[LINE])
			if FILE[LINE].startswith("_____"):
				STATE = False
				break
			else:
				if GetDistro.search(FILE[LINE]):
					AffectedProductLine=FILE[LINE].strip().replace('<br>', '')
					if AffectedProductLine.endswith("-EXTRA"):
						# skip it
						continue
					elif AffectedProductLine.endswith("-SECURITY"):
						# skip it
						continue
					elif AffectedProductLine.endswith("-BCL"):
						# skip it
						continue
					elif AffectedProductLine.endswith("-CLIENT-TOOLS"):
						# skip it
						continue
					elif AffectedProductLine.endswith("-PUBCLOUD"):
						# skip it
						continue
					else:
						APLIST.append(AffectedProductLine)
		elif AffectedProductList.search(FILE[LINE]):
			STATE = True
	if( VERBOSE ):
		print(DISPLAY.format('Products', str(len(APLIST))))
#	print("  <getAffectedProducts: APLIST=" + str(APLIST))
#	sys.exit(3)

def getDistribution(AP):
#	print "  >getDistribution"
	global DISTRO
	if "-SP" in AP:
		AP = AP.replace("-SP", " SP")
	if "-LTSS" in AP:
		AP = AP.replace("-LTSS", " LTSS")
#	print " Fixed", AP
	THIS_DISTRO = ''
	OSDISTRO = -1
	SP = 0
	LTSS_STR = ''
	DISTRO_TMP = AP.split()
#	print 'DISTRO_TMP', DISTRO_TMP
	if AP.lower().endswith(" ltss"):
		LTSS_STR = "ltss"
	for TEXT in DISTRO_TMP:
#		print " TEXT = " + str(TEXT) + "; OSDISTRO = " + str(OSDISTRO)
		if( OSDISTRO >= 0 ):
			if "SP" in TEXT:
				SP = TEXT.replace('SP', '')
				break
		elif TEXT.endswith("-EXTRA"):
			THIS_DISTRO="Exclude"
		elif TEXT.isdigit():
			OSDISTRO = int(TEXT)
	if( THIS_DISTRO != "Exclude" ):
		DISTRO = str(OSDISTRO) + "." + str(SP) + "." + str(LTSS_STR)
	if( VERBOSE ):
		print(DISPLAY.format('Distribution', AP))
#	print "  <getDistribution: DISTRO=" + str(DISTRO)
	
def getPackages(AFFECTED_DISTRO):
#	print("\n=======================================")
#	print("  >getPackages(" + str(AFFECTED_DISTRO) + ")")
	global PACKAGES
	global PACKAGE_ERRORS
	IN_PACKAGE_LIST = False
	PROD_LIST = False
	getDistribution(AFFECTED_DISTRO)

#	print(DISTRO)
#	print(DISTRO.split('.'))
	(VER_MAJOR, VER_MINOR, LTSS_STR) = DISTRO.split('.')
#	print("VER_MAJOR='" + str(VER_MAJOR) + "', VER_MINOR='" + str(VER_MINOR) + "', LTSS_STR='" + str(LTSS_STR) + "'")
#	print(AFFECTED_DISTRO)
#	print()
	PL = re.compile(AFFECTED_DISTRO, re.IGNORECASE)
	for LINE in FILE:
		TEXT = FILE[LINE].strip().replace('<br>', '')
#		if "SUSE Linux Enterprise" in TEXT:
#			print('TEXT', TEXT)
		if( IN_PACKAGE_LIST ):
			if TEXT.startswith("References:"):
#				print("END Package List")
				IN_PACKAGE_LIST = False
				PROD_LIST = False
			elif( PROD_LIST ):
				if TEXT.startswith('-'):
					if not PL.search(TEXT):
						PROD_LIST = False
				elif( len(TEXT) > 0 ):
					if TEXT.endswith('):'):
						continue
					elif TEXT.endswith(']:'):
						continue
					else:
#						print("Check package = " + str(TEXT))
						PARTS = TEXT.split('-')
						VERSION = PARTS[-2] + '-' + PARTS[-1]
						del PARTS[-1]
						del PARTS[-1]
						NAME = '-'.join(PARTS)
#						print("NAME|VERSION  = " + str(NAME) + "|" + str(VERSION))
						if NAME in PACKAGES:
							if( PACKAGES[NAME] != VERSION ):
								PACKAGE_ERRORS += 1
#								print " ERROR: Package version conflict for " + str(NAME) + ": " + str(PACKAGES[NAME]) + " and " + str(VERSION)
								PACKAGES[NAME] = VERSION
						else:
							PACKAGES[NAME] = VERSION
#						print("PACKAGES(" + str(len(PACKAGES)) + ") = " + str(PACKAGES) + "\n")
			elif PL.search(TEXT):
#				print("Product Found:", TEXT)
				PROD_LIST = True
		elif TEXT.startswith("Package List:"):
			IN_PACKAGE_LIST = True

#	for KEY in PACKAGES:
#		print("  '" + str(KEY) + "': '" + str(PACKAGES[KEY]) + "',")
#	print("  <getPackages: " + str(len(PACKAGES)))

def cleanUp():
#	print("  >cleanUp")
	global MD
	if( os.path.exists(MD['file']) ):
		try:
			os.unlink(MD['file'])
		except Exception as error:
			print((" ERROR: Cannot delete " + str(MD['file']) + ": " + str(error)))
#	print("  <cleanUp")

def usage():
    print("sapat.py [-qs] <advisory_url>")
    print()

def showSummary():
	global CNT
	print((" Patterns: " + str(CNT['patterns']) + ", Success: " + str(CNT['success']) + ", Skipped: " + str(CNT['skipped']) + ", Duplicates: " + str(CNT['duplicate']) + ", Errors: " + str(CNT['errors'])))

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
for AP in APLIST:
	CNT['patterns'] += 1

	PACKAGES = {}
	PACKAGE_ERRORS = 0
	getPackages(AP)
	if( PACKAGE_ERRORS > 0 ):
		CNT['errors'] += 1
		FAILURE = True
		ERR_PKG_VERSION = True
		if( VERBOSE ):
			print(" ERROR: Detected " + str(PACKAGE_ERRORS) + " package version errors for " + str(AP))
	if( len(PACKAGES) == 0 ):
		FAILURE = True
		CNT['errors'] += 1
		ERR_PKG_EMPTY = True
		if( VERBOSE ):
			print(" ERROR: Empty package list for " + str(AP))

	createPattern()
#print("CNT='" + str(CNT))
cleanUp()
if( FAILURE ):
	if( CNT['errors'] < CNT['patterns'] ):
		if( VERBOSE ):
			print(DISPLAY.format('Status', '** PARTIAL **'))
		RCODE = 128
	else:
		if( VERBOSE ):
			print(DISPLAY.format('Status', '** FAILURE **'))
		RCODE = 255
elif( len(DISTRO) < 1 ):
	CNT['skipped'] += 1
	if( VERBOSE ):
		print(DISPLAY.format('Status', '** SKIPPED **'))
		print(DISPLAY.format('  Message', 'No Valid Distros to Process'))
	RCODE = 1
else:
	CNT['success'] += 1
	if( VERBOSE ):
		print(DISPLAY.format('Status', 'Success'))
if( not QUIET ):
	showSummary()

sys.exit(RCODE)

