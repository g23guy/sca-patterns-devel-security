#!/usr/bin/python3
SVER = '2.0.0-beta4'
##############################################################################
# sagen.py - Security Advisory Announcement Pattern Generator
# Copyright (C) 2022 SUSE LLC
#
# Description:  Creates a python security advisory pattern from HTML page
# Modified:     2022 Oct 01
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
import requests
import signal
import configparser
from pathlib import Path

# Global Options
today = datetime.datetime.today()
conf_file = '/etc/opt/autogen/autogen.conf'
dirbase = ''
dirlog = ''
dirpat = ''
manifest_file = '' # Records the security URL and target URLs processed successfully
urlbase = 'https://lists.suse.com/pipermail/sle-security-updates/'
urllist = ''
target_url = ''
all_counters = {'pattern_count_current': 0, 'pattern_count_total': 0, 'a_errors': 0, 'patterns_evaluated': 0, 'patterns_generated': 0, 'patterns_duplicated': 0, 'p_errors': 0}

said_file_pairs = {}
LOG_QUIET = 0	# turns off messages
LOG_MIN = 1	# minimum messages
LOG_NORMAL = 2	# normal, but significant, messages
LOG_VERBOSE = 3	# detailed messages
LOG_DEBUG = 4	# debug-level messages
log_level = LOG_MIN

# Functions and Classes
def title():
	"Display the program title"
	print("#############################################################################")
	print("# Security Advisory Announcement Pattern Generator v" + str(SVER))
	print("# for the SCA Tool")
	print("#############################################################################")

def usage():
	"Displays usage information"
	print("Usage: sagen.py [options]")
	print()
	print("Options:")
	print("  -h           Display this help")
	print("  -q           Do not display output, run quietly")
	print("  -l <level>   Set log level")
	print("     0 Quiet, 1 Minimal, 2 Normal, 3 Verbose, 4 Debug")
	print()

def signal_handler(sig, frame):
	print("\n\nAborting...")
	show_summary()
	clean_up()
	sys.exit(0)

class ProgressBar():
	"Initialize and update progress bar class"
	def __init__(self, prefix, bar_width, total):
		self.prefix = prefix
		self.bar_width = bar_width
		self.total = total
		self.out = sys.stdout

	def __str__(self):
		return 'class %s(\n  prefix=%r \n  bar_width=%r \n  total=%r\n)' % (self.__class__.__name__, self.prefix, self.bar_width, self.total)

	def update(self, count):
		percent_complete = int(100*count/self.total)
		current_progress = int(self.bar_width*count/self.total)
		print("{}[{}{}] {:3g}% {:3g}/{}".format(self.prefix, "#"*current_progress, "."*(self.bar_width-current_progress), percent_complete, count, self.total), end='\r', file=self.out, flush=True)

	def finish(self):
		print("\n", flush=True, file=self.out)

class DisplayMessages():
	"Display message string for a given log level"
	LOG_QUIET	= 0	# turns off messages
	LOG_MIN		= 1	# minimum messages
	LOG_NORMAL	= 2	# normal, but significant, messages
	LOG_VERBOSE	= 3	# detailed messages
	LOG_DEBUG	= 4	# debug-level messages
	DISPLAY = "{0:25} = {1}"

	def __init__(self, level=LOG_MIN):
		self.level = level
	def __str__ (self):
		return "class %s(level=%r)" % (self.__class__.__name__,self.level)

	def get_level(self):
		return self.level

	def set_level(self, level):
		if( level >= self.LOG_DEBUG ):
			self.level = self.LOG_DEBUG
		else:
			self.level = level

	def __write_msg(self, level, msgtag, msgstr):
		if( level <= self.level ):
			print(self.DISPLAY.format(msgtag, msgstr))

	def min(self, msgtag, msgstr):
		"Write the minium amount of messages"
		self.__write_msg(self.LOG_MIN, msgtag, msgstr)

	def normal(self, msgtag, msgstr):
		"Write normal, but significant, messages"
		self.__write_msg(self.LOG_NORMAL, msgtag, msgstr)

	def verbose(self, msgtag, msgstr):
		"Write more verbose informational messages"
		self.__write_msg(self.LOG_VERBOSE, msgtag, msgstr)

	def debug(self, msgtag, msgstr):
		"Write all messages, including debug level"
		self.__write_msg(self.LOG_DEBUG, " > " + str(msgtag), msgstr)

class SecurityAnnouncement():
	"Security announcement class"
	IDX_LAST = -1
	IDX_FIRST = 0
	AUTHOR = 'Jason Record <jason.record@suse.com>'

	def __init__(self, DisplayMessages, dirbase, target_url, file):
		self.dirbase = dirbase
		self.dirlog = self.dirbase + 'logs/'
		self.dirpat = self.dirbase + 'patterns/'
		self.file = file
		self.target_url = target_url
		self.safilepath = self.dirlog + self.file
		self.sauri = self.target_url + self.file
		self.loaded_file = []
		self.main_package = ''
		self.announcement_id = ''
		self.rating = ''
		self.package_lists = []
		self.patterns_created = {}
		self.stat = {'patterns_evaluated': 0, 'patterns_generated': 0, 'patterns_duplicated': 0, 'a_errors': 0, 'p_errors': 0}
		self.__load_file()
		self.__get_metadata()
		self.__get_package_lists()

	def __str__(self):
		return 'class %s(\n  package_lists=%r \n  safilepath=%r \n  sauri=%r \n  main_package=%r \n  announcement_id=%r \n  rating=%r\n)' % (self.__class__.__name__,self.package_lists, self.safilepath, self.sauri, self.main_package, self.announcement_id, self.rating)

	def __cleanup(self):
		print("!Cleanup skipped")
		pass

	def __load_file(self):
		msg.debug('Loading file', self.safilepath)
		try:
			f = open(self.safilepath, "r")
		except Exception as error:
			msg.min("ERROR: Cannot open", str(self.safilepath) + ": " + str(error))
			self.stat['a_errors'] += 1
			self.__cleanup()
			sys.exit()

		invalid = re.compile(r'>Object not found!<', re.IGNORECASE)
		for line in f.readlines():
			line = line.strip("\n")
			if invalid.search(line):
				self.loaded_file = []
				msg.min("ERROR: Invalid file", str(safilepath))
				self.stat['a_errors'] += 1
				f.close()
				self.__cleanup()
				sys.exit()
			self.loaded_file.append(line)
		f.close()

	def __get_metadata(self):
		"Pulls the package name, announcement ID and rating"
		suse_default = re.compile("SUSE Security Update:", re.IGNORECASE)
		for line in self.loaded_file:
			text = line.strip().replace('<br>', '') # clean up line
			if suse_default.search(text):
				if "java" in text.lower():
					self.main_package = "Java"
				elif "apache" in text.lower():
					self.main_package = "Apache"
				elif "kerberos" in text.lower():
					self.main_package = "Kerberos"
				else:
					self.main_package = re.sub('[,]', '', text.split()[self.IDX_LAST])
			elif text.startswith("Announcement ID:"):
				self.announcement_id = text.split()[self.IDX_LAST]
			elif text.startswith("Rating:"):
				self.rating = text.split()[self.IDX_LAST].title()
		msg.debug('self.main_package', self.main_package)
		msg.debug('self.announcement_id', self.announcement_id)
		msg.debug('self.rating', self.rating)


	def __get_package_lists(self):
		"Creates a list of dictionaries for each distribution found"
		in_list = False
		in_packages = False
		header = True
		for line in self.loaded_file:
			text = line.strip().replace('<br>', '') # clean up line
			if( in_list ):
				if text.startswith('References:'):
					in_list = False
					break
				else:
					if( in_packages ):
						if( header ):
							header = False
							continue
						elif( len(text) == 0 ):
							in_packages = False
							self.package_lists.append(this_list)
						else:
							pkg_parts = text.split('-')
							pkg_version = pkg_parts[-2] + '-' + pkg_parts[-1]
							del pkg_parts[-1]
							del pkg_parts[-1]
							pkg_name = '-'.join(pkg_parts)
							# Might need to check for pre-existing package before assigning
							this_list['packages'][pkg_name] = pkg_version
					elif text.startswith('-'):
					# Example:  - SUSE Linux Enterprise Module for Basesystem 15-SP3-BCL (aarch64 ppc64le s390x x86_64):
					#						dwarves-1.22-150300.7.3.1
					#						elfutils-0.177-150300.11.3.1
					#
					# this_list assignment example
					# label: 		SUSE Linux Enterprise Module for Basesystem 15 SP3 BCL
					# major: 		15
					# minor: 		3
					# ltss:			False
					# tag:			BCL
					# archs: 		['aarch64', 'ppc64le', 's390x', 'x86_64']
					# packages:		{'dwarves': '1.22-150300.7.3.1', 'elfutils': '0.177-150300.11.3.1'}
						this_list = {'label': '', 'major': -1, 'minor': -1, 'ltss': False, 'tag': '', 'archs': [], 'packages': {}}
						in_packages = True
						header = True
						# Might need to check of more than one ( character is in the string, for now I'm assuming only one.
						parts = text.split('(')
						this_list['label'] = parts[self.IDX_FIRST].replace('-', ' ')[2:].strip() #Everything to the left of the first ( excluding the leading "- ".
						this_list['archs'] = parts[self.IDX_LAST].rstrip("):").split()
						parts = this_list['label'].split()
						for part in parts:
							if part[:1].isdigit():
								if( "." in part ):
									this_list['major'], this_list['minor'] = part.split('.')
								else:
									this_list['major'] = part
							elif( part.startswith('SP') ):
								this_list['minor'] = part[2:] # remove the SP in part
							elif( 'ltss' in part.lower() ):
								this_list['ltss'] = True
						if( int(this_list['minor']) < 0 ):
							this_list['minor'] = 0
						if( "SP" not in parts[self.IDX_LAST] and 'ltss' not in parts[self.IDX_LAST].lower() and not parts[self.IDX_LAST][:1].isdigit() ):
							this_list['tag'] = parts[self.IDX_LAST]
			elif text.startswith('Package List:'):
				in_list = True
		msg.debug('self.package_lists', self.package_lists)

	def __create_pattern(self, distro_index, pattern_tag):
		TODAY = datetime.date.today()
		if( len(pattern_tag) > 0 ):
			tag = "_" + str(pattern_tag) + "_"
		else:
			tag = "_"
		if( self.package_lists[distro_index]['ltss'] ):
			add_ltss_string = ".ltss"
		else:
			add_ltss_string = ""
		pattern_filename = str(self.main_package).lower() + "_" + str(self.announcement_id) + str(tag) + str(self.package_lists[distro_index]['major']) + "." + str(self.package_lists[distro_index]['minor']) + add_ltss_string + ".py"
		pattern_filename = pattern_filename.replace(':', '_')

		# Build pattern file content
		CONTENT = "#!/usr/bin/python3\n#\n"
		CONTENT += "# Title:       " + str(self.rating) +" Security Announcement for " + str(self.main_package).replace(':', '') + " " + str(self.announcement_id) + "\n"
		if( self.package_lists[distro_index]['ltss'] ):
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise " + str(self.package_lists[distro_index]['major']) + " SP" + str(self.package_lists[distro_index]['minor']) + " LTSS\n"
		else:
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise " + str(self.package_lists[distro_index]['major']) + " SP" + str(self.package_lists[distro_index]['minor']) + "\n"
		CONTENT += "# URL:         "  + str(self.sauri) + "\n"
		CONTENT += "# Source:      Security Announcement Generator (sagen.py) v" + str(SVER) + "\n"
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
		CONTENT += "#  Authors/Contributors:\n#   " + self.AUTHOR + "\n#\n"
		CONTENT += "##############################################################################\n\n"
		CONTENT += "import os\n"
		CONTENT += "import Core\n"
		CONTENT += "import SUSE\n\n"
		CONTENT += "META_CLASS = \"Security\"\n"
		CONTENT += "META_CATEGORY = \"SLE\"\n"
		CONTENT += "META_COMPONENT = \"" + str(self.main_package) + "\"\n"
		CONTENT += "pattern_filename = os.path.basename(__file__)\n"
		CONTENT += "PRIMARY_LINK = \"META_LINK_Security\"\n"
		CONTENT += "OVERALL = Core.TEMP\n"
		CONTENT += "OVERALL_INFO = \"NOT SET\"\n"
		CONTENT += "OTHER_LINKS = \"META_LINK_Security=" + str(self.sauri) + "\"\n"
		CONTENT += "Core.init(META_CLASS, META_CATEGORY, META_COMPONENT, pattern_filename, PRIMARY_LINK, OVERALL, OVERALL_INFO, OTHER_LINKS)\n\n"
		if( self.package_lists[distro_index]['ltss'] ):
			CONTENT += "LTSS = True\n"
		else:
			CONTENT += "LTSS = False\n"
		CONTENT += "NAME = '" + self.main_package + "'\n"
		CONTENT += "MAIN = ''\n"
		CONTENT += "SEVERITY = '" + self.rating + "'\n"
		CONTENT += "TAG = '" + self.announcement_id + "'\n"
		CONTENT += "PACKAGES = {}\n"
		CONTENT += "SERVER = SUSE.getHostInfo()\n\n"
		CONTENT += "if ( SERVER['DistroVersion'] == " + str(self.package_lists[distro_index]['major']) + "):\n"
		CONTENT += "\tif ( SERVER['DistroPatchLevel'] == " +  str(self.package_lists[distro_index]['minor']) + " ):\n"
		CONTENT += "\t\tPACKAGES = {\n"

		for key in sorted(self.package_lists[distro_index]['packages'].keys()):
			CONTENT += "\t\t\t'" + str(key) + "': '" + str(self.package_lists[distro_index]['packages'][key]) + "',\n"

		CONTENT += "\t\t}\n"
		CONTENT += "\t\tSUSE.securityAnnouncementPackageCheck(NAME, MAIN, LTSS, SEVERITY, TAG, PACKAGES)\n"
		CONTENT += "\telse:\n"
		CONTENT += "\t\tCore.updateStatus(Core.ERROR, \"ERROR: \" + NAME + \" Security Announcement: Outside the service pack scope\")\n"
		CONTENT += "else:\n"
		CONTENT += "\tCore.updateStatus(Core.ERROR, \"ERROR: \" + NAME + \" Security Announcement: Outside the distribution scope\")\n"
		CONTENT += "Core.printPatternResults()\n\n"


		# Write the content to a pattern on disk
		pattern_file = self.dirpat + pattern_filename
		self.stat['patterns_evaluated'] += 1
		if( os.path.exists(pattern_file) ):
			msg.debug('Pattern', str(pattern_filename) + " (" +  str(len(self.package_lists[distro_index]['packages'])) + " packages)")
			msg.debug("ERROR Duplicate", "Pattern " + pattern_file)
			self.stat['patterns_duplicated'] += 1
#			cleanUp()
	#		sys.exit(4)
		else:
			try:
				f = open(pattern_file, "w")
				f.write(CONTENT)
				f.close()
				os.chmod(pattern_file, 0o755)
				msg.verbose(' + Pattern', str(pattern_filename) + " (" +  str(len(self.package_lists[distro_index]['packages'])) + " packages)")
				self.stat['patterns_generated'] += 1
				self.patterns_created[pattern_filename] = len(self.package_lists[distro_index]['packages'])
			except Exception as error:
				msg.verbose(" + ERROR: Cannot create " + str(pattern_file) + ": " + str(error))
				self.stat['p_errors'] += 1

	def get_stats(self):
		"Return the class statistics"
		msg.debug("Stats", str(self.stat))
		return self.stat

	def get_patterns(self):
		"Return the patterns created with the number of associated packages"
		msg.debug("Patterns", str(self.patterns_created))
		return self.patterns_created

	def get_list(self, regexstr):
		"Return a list of indeces for the matching package list(s) based on the regex expression given. The regex ignores case."
		getdistro = re.compile(regexstr, re.IGNORECASE)
		distros = []
		for i in range(len(self.package_lists)):
			if getdistro.search(self.package_lists[i]['label']):
				distros.append(i)
		return distros

	def create_patterns(self, create_list, pattern_tag):
		"Create patterns for the given index list"
		if( len(create_list) > 0 ):
			for i in create_list:
				self.__create_pattern(i, pattern_tag)

def initialize_manifest():
	manifest['metadata'] = {}
	manifest['metadata']['run_date'] = today.strftime("%c")
	manifest['metadata']['pattern_count_total'] = str(0)
	manifest['metadata']['pattern_count_current'] = str(0)
	manifest['metadata']['percent_complete'] = str(0)
	manifest['metadata']['patterns_evaluated'] = str(0)
	manifest['metadata']['patterns_generated'] = str(0)
	manifest['metadata']['patterns_duplicated'] = str(0)
	manifest['metadata']['urllist'] = urllist
	manifest['metadata']['urlbase'] = urlbase
	manifest['metadata']['target_url'] = target_url
	manifest['metadata']['dirbase'] = dirbase
	manifest['metadata']['dirlog'] = dirlog
	manifest['metadata']['dirpat'] = dirpat

def convert_date(given_str):
	"Converts given string to valid date for URL retrival"
	converted_str = 'INVALID'
	MONTHS = {1: 'January', 2: 'February', 3: 'March', 4: 'April', 5: 'May', 6: 'June', 
	7: 'July', 8: 'August', 9: 'September', 10: 'October', 11: 'November', 12: 'December', 
	'jan': 'January', 'feb': 'February', 'mar': 'March', 'apr': 'April', 'may': 'May', 'jun': 'June', 
	'jul': 'July', 'aug': 'August', 'sep': 'September', 'oct': 'October', 'nov': 'November', 'dec': 'December'}
	MONTHS_DIGIT = {'January': '01', 'February': '02', 'March': '03', 'April': '04', 'May': '05', 'June': '06', 
	'July': '07', 'August': '08', 'September': '09', 'October': '10', 'November': '11', 'December': '12'}
	this_year = today.strftime("%Y")
	this_month = today.strftime("%B")
	use_year = ''
	use_month = ''
	if( len(given_str) > 0 ):
		if( '-' in given_str ):
			parts = given_str.split('-')
		elif( '/' in given_str ):
			parts = given_str.split('/')
		else:
			parts = [given_str, '0']

		#print(parts)
		for part in parts:
			if( part.isdigit() ):
				part = int(part)
				if( part > 0 ):
					if( part > 12 ): # Assume it's the requested year
						if( part > 99 ):
							use_year = str(part)
						else:
							use_year = "20" + str(part)
					else: # Assume it's the requested month
						if( part in MONTHS.keys() ):
							use_month = MONTHS[part]
						else:
							msg.min("ERROR", "Invalid date string - " + str(given_str))
							sys.exit(3)
			else:
				part = part[:3].lower()
				if( part in MONTHS.keys() ):
					use_month = MONTHS[part]
				else:
					msg.min("ERROR", "Invalid date string - " + str(given_str))
					sys.exit(3)
		if( len(use_year) == 0 ):
			use_year = this_year
		if( len(use_month) == 0 ):
			use_month = this_month
		converted_str = str(use_year) + "-" + str(use_month)
	else:
		converted_str = today.strftime("%Y-%B")
	msg.debug("Date Conversion", "given_str=" + str(given_str) + ", converted_str=" + str(converted_str))
	return converted_str

def load_manifest():
	"Load the manifest_file into the configparser object"
	msg.verbose("Loading Manifest", manifest_file)
	if( os.path.exists(manifest_file) ):
		manifest.read(manifest_file)
		status = True
	else:
		status = False
	return status

def save_manifest():
	"Save the configuration to manifest_file"
	msg.verbose("Saving Manifest", manifest_file + "\n")
	with open(manifest_file, 'w') as configfile:
		manifest.write(configfile)

def create_sles_patterns(security):
	"Create SLES specific patterns available in the security class instance"
	slespats = security.get_list('SUSE Linux Enterprise Server [1-9]|SUSE Linux Enterprise Module for Basesystem [1-9]')
	pat_tag = 'sles'
	msg.debug("Pattern indeces", str(pat_tag) + str(slespats))
	security.create_patterns(slespats, pat_tag)

def delete_manifest_files():
	"Delete all files logged in the manifest_file"
	for section in manifest.sections():
		if( section == "metadata" ):
			continue
		else:
			for sectionkey, sectionvalue in dict(manifest.items(section)).items():
				if( sectionkey.lower() == "status" ):
					continue
				else:
					delete_file = manifest['metadata']['dirpat'] + sectionkey
					if( os.path.exists(delete_file) ):
						msg.verbose("Deleting", delete_file)
						os.unlink(delete_file)
					else:
						msg.verbose("Not found", delete_file)
			delete_section = manifest['metadata']['dirlog'] + section
			if( os.path.exists(delete_section) ):
				msg.verbose("Deleting", delete_section)
				os.unlink(delete_section)
			else:
				msg.verbose("Not found", delete_section)
	if( os.path.exists(manifest_file) ):
		msg.verbose("Deleting", manifest_file)
		os.unlink(manifest_file)
	else:
		msg.verbose("Not found", manifest_file)
	msg.normal("Delete manifest files", "Complete")

def evaluate_manifest():
	"Configure the manifest to start with the correct file from the list of announcements needing processing"
	if( manifest.getint('metadata', 'pattern_count_total') > 0 ):
		pass
	else:
		msg.debug("Security Announcement files for processing", "Assign All")
		for said, safile in said_file_pairs.items():
			manifest[safile] = {}
			manifest[safile]['status'] = 'Assigned'


def how_to_proceed(question, default='abort'):
	"Prompt to restart, continue or abort"
	rc = -1
	RC_CONTINUE = 0
	RC_RESET = 1
	RC_ABORT = 2

	valid = {"r": RC_RESET, "reset": RC_RESET, "c": RC_CONTINUE, "continue": RC_CONTINUE, "cont": RC_CONTINUE, "a": RC_ABORT, "abort": RC_ABORT}

	if default == 'continue':
		prompt = " [Reset, (C)ontinue, Abort]? "
	elif default == 'reset':
		prompt = " [(R)eset, Continue, Abort]? "
	elif default == 'abort':
		prompt = " [Reset, Continue, (A)bort]? "
	else:
		raise ValueError("Invalid default answer: '%s'" % default)

	while( rc < 0 ):
		sys.stdout.write(question + prompt)
		choice = input().lower()
		if default is not None and choice == "":
			rc = valid[default]
		elif choice in valid:
			rc = valid[choice]
		else:
			sys.stdout.write("Please respond with 'r' to reset, 'c' to continue or 'a' to abort.\n")

	if( rc == RC_ABORT ):
		sys.exit(5)
	elif( rc == RC_RESET ):
		delete_manifest_files()
		initialize_manifest()
		evaluate_manifest()
	elif( rc == RC_CONTINUE ):
		evaluate_manifest()


def prep_archive_threads():
	"Prepare the archive threads and manifest with announcements for the selected archive location"
	IDX_FILENAME = 1
	IDX_SAIDPART = 2
	IDX_SAID = 0

	try:
		x = requests.get(target_url)
	except Exception as error:
		msg.min(' ERROR', "Cannot download " + str(target_url) + ": " + str(error))
		sys.exit(2)

	if( x.status_code == 200 ):
		data = x.text.split('\n')
		distrotag = re.compile('\<LI>\<A HREF.*>SUSE-SU-', re.IGNORECASE)
		for line in data:
			if distrotag.search(line):
				# Example: <LI><A HREF="011729.html">SUSE-SU-2022:2608-1: important: Security update for booth
				htmlfile = line.split('"')[IDX_FILENAME] # parse out the HREF filename
				htmlsaid = line.split('"')[IDX_SAIDPART].split()[IDX_SAID].strip('>:')
				said_file_pairs[htmlsaid] = htmlfile
	else:
		msg.min("ERROR " + str(x.status_code), "URL download failure - " + str(target_url))
		sys.exit(2)

	msg.debug("File Dictionary", str(said_file_pairs))

	all_counters['pattern_count_total'] = len(said_file_pairs)
	manifest_pattern_count_total = manifest.getint('metadata', 'pattern_count_total') 
	manifest_pattern_count_current = manifest.getint('metadata', 'pattern_count_current')
#	print("manifest_pattern_count_current=" + str(manifest_pattern_count_current))
#	print("manifest_pattern_count_total=" + str(manifest_pattern_count_total))
#	print("all_counters['pattern_count_total']=" + str(all_counters['pattern_count_total']))
	if( manifest_pattern_count_total == 0 ):
		print("Starting new")
		initialize_manifest()
		evaluate_manifest()
		manifest['metadata']['pattern_count_total'] = str(all_counters['pattern_count_total'])
		manifest['metadata']['pattern_count_current'] = str(all_counters['pattern_count_current'])
	elif( manifest_pattern_count_current < manifest_pattern_count_total ):
		how_to_proceed("Previous run incomplete", default='abort')
	elif( manifest_pattern_count_total != all_counters['pattern_count_total']):
		newcount = all_counters['pattern_count_total'] - manifest_pattern_count_total
		how_to_proceed("Additional announcements found since last run: " + str(newcount), default='continue')
	elif( manifest_pattern_count_current == manifest_pattern_count_total and manifest_pattern_count_total == all_counters['pattern_count_total']):
		how_to_proceed("No new announcements to process", default='abort')
	else:
		how_to_proceed("Unknown manifest data", default='reset')

def process_archive_threads():
	"Process the security announcement thread archive"
	msg.min('Announcement Source', urllist)
	progress_bar_width = 50

	zsize = len(str(all_counters['pattern_count_total']))
	msg.min("Announcements to Process", str(all_counters['pattern_count_total']) + "\n")
	if( log_level == LOG_MIN ):
		bar = ProgressBar("Processing: ", progress_bar_width, all_counters['pattern_count_total'])

	for sa_id, sa_file in said_file_pairs.items():
		sa_url = target_url + sa_file
		all_counters['pattern_count_current'] += 1
		if( manifest[sa_file]['status'] == 'Found' ):
			continue
		else:
			manifest[sa_file]['status'] = 'Pending'
		msg.verbose("\n= Get Security URL", str(sa_id) + " (" + str(sa_file) + ")")
		try:
			msg.debug("Security URL", sa_url)
			url = requests.get(sa_url)
		except Exception as error:
			manifest[sa_file]['status'] = 'Download_Error'
			msg.summary(' ERROR', "Cannot download " + str(sa_url) + ": " + str(error))
			continue

		if( url.status_code == 200 ):
			sa_local = dirlog + sa_file
			msg.debug("Security file", sa_local)
			try:
				f = open(sa_local, 'wb')
				f.write(url.content)
				f.close()
			except Exception as error:
				msg.normal(' ERROR', "Cannot write file " + str(sa_url) + ": " + str(error))
				continue
			security = SecurityAnnouncement(msg, dirbase, target_url, sa_file)
			create_sles_patterns(security)
			announcement_counters = security.get_stats()
			patterns_written = security.get_patterns()
			if( log_level == LOG_MIN ):
				bar.update(all_counters['pattern_count_current'])
			else:
				msg.normal("Processed File [" +
				str(all_counters['pattern_count_current']).zfill(zsize) + "/" +
				str(all_counters['pattern_count_total']) + "]", str(sa_id) + " (" + str(sa_file) + "), Patterns Generated: " + str(announcement_counters['patterns_generated']) + ", Duplicates: " + str(announcement_counters['patterns_duplicated']))

			manifest['metadata']['pattern_count_current'] = str(all_counters['pattern_count_current'])
			manifest['metadata']['percent_complete'] = str(int(all_counters['pattern_count_current']*100/all_counters['pattern_count_total']))
			for key, value in dict(patterns_written).items():
				manifest[sa_file][key] = str(value)
			for key in announcement_counters.keys():
				all_counters[key] += announcement_counters[key]
			msg.debug("All Counters", str(all_counters))
			manifest[sa_file]['status'] = 'Complete'

	if( log_level == LOG_MIN ):
		bar.finish()
	manifest['metadata']['patterns_evaluated'] = str(all_counters['patterns_evaluated'])
	manifest['metadata']['patterns_generated'] = str(all_counters['patterns_generated'])
	manifest['metadata']['patterns_duplicated'] = str(all_counters['patterns_duplicated'])
# DEBUG HERE
#		if( all_counters['pattern_count_current'] > 1 ):
#			break
# DEBUG HERE

def show_summary():
	DISPLAY = " {0:25} = {1}"
	print("Summary")
	print(DISPLAY.format("Processed", all_counters['pattern_count_current']))
	print(DISPLAY.format("Patterns Evaluated", all_counters['patterns_evaluated']))
	print(DISPLAY.format("Patterns Generated", all_counters['patterns_generated']))
	print(DISPLAY.format("Duplicate Patterns", all_counters['patterns_duplicated']))
	print(DISPLAY.format("Announcement Errors", all_counters['a_errors']))
	print(DISPLAY.format("Pattern Errors", all_counters['p_errors']))
	print("\nDetails")
	print(DISPLAY.format("Announcements URL", target_url))
	print(DISPLAY.format("Log Directory", dirlog))
	print(DISPLAY.format("Pattern Directory", dirpat))
	print('\n')
	#print("List Configuration Data")
	#for section in manifest.sections():
	#	print("[%s]" % section)
	#	for options in manifest.options(section):
	#		print("%s = %s" % (options, manifest.get(section, options)))
	#	print()

def clean_up():
	save_manifest()
	
def load_config_file():
	global dirbase, dirlog, dirpat
	config_file_dict = {}

	try:
		f = open(conf_file, "r")
	except Exception as error:
		msg.min("ERROR: Cannot open", str(conf_file) + ": " + str(error))
		sys.exit(3)

	for line in f.readlines():
		line = line.strip("\n")
		key, value = line.split('=')
		value = value.strip('"')
		config_file_dict[key] = value.strip('"')
	f.close()
	#print(config_file_dict)
	
	if config_file_dict['PATDIR_BASE']:
		dirbase = config_file_dict['PATDIR_BASE'] + "/"
		dirlog = dirbase + '/logs/'
		dirpat = dirbase + '/patterns/'
	else:
		title()
		print("Error: PATDIR_BASE not found in " + conf_file)
		print()
		sys.exit(3)

##############################################################################
# Main
##############################################################################

def main(argv):
	"main entry point"
	global today, conf_file, log_level, all_counters, target_url, dirbase, dirlog, dirpat
	global urlbase, urllist, manifest_file, said_file_pairs, SVER

	if( os.path.exists(conf_file) ):
		load_config_file()
	else:
		title()
		print("Error: Configuration file not found - " + conf_file)
		print()
		sys.exit(1)

	user_logging = -1
	try:
		(optlist, args) = getopt.gnu_getopt(argv[1:], "hql:r:")
	except getopt.GetoptError as exc:
		title()
		print("Error:", exc, file=sys.stderr)
		sys.exit(2)
	for opt in optlist:
		if opt[0] in {"-h"}:
			usage()
			sys.exit(0)
		elif opt[0] in {"-q"}:
			log_level = LOG_QUIET
		elif opt[0] in {"-l"}:
			if( opt[1].isdigit() ):
				user_logging = int(opt[1])
			else:
				if( opt[1].lower().startswith("qui") ):
					log_level = LOG_QUIET
				elif( opt[1].lower().startswith("min") ):
					log_level = LOG_MIN
				elif( opt[1].lower().startswith("norm") ):
					log_level = LOG_NORMAL
				elif( opt[1].lower().startswith("verb") ):
					log_level = LOG_VERBOSE
				elif( opt[1].lower().startswith("debug") ):
					log_level = LOG_DEBUG
				else:
					print("Invalid log level, using default")
		elif opt[0] in {"-r"}:
			print("WARNING: Range option is not yet implemented\n")

	if len(args) > 0:
		given_date = '-'.join(args)
	else:
		given_date = ''

	if( user_logging >= LOG_QUIET ):
		log_level = user_logging

	if( log_level > LOG_QUIET ):
		title()

	msg.set_level(log_level)

	urllist = convert_date(given_date)
	target_url = urlbase + urllist + "/"

	#print(msg)
	manifest_file = dirlog + "manifest-sagen_" + urllist + ".cfg"
	if not ( load_manifest() ):
		initialize_manifest()
#	else:
#		print("List Configuration Data")
#		for section in manifest.sections():
#			print("[%s]" % section)
#			for options in manifest.options(section):
#				print("%s = %s" % (options, manifest.get(section, options)))
#			print()

	prep_archive_threads()
	process_archive_threads()
	if( log_level > LOG_QUIET ):
		show_summary()
	clean_up()

# Entry point
if __name__ == "__main__":
	manifest = configparser.ConfigParser()
	manifest.optionxform = str # Ensures manifest keys are saved as case sensitive and not lowercase
	signal.signal(signal.SIGINT, signal_handler)
	msg = DisplayMessages()
	main(sys.argv)


