#!/usr/bin/env python

import argparse
import arrow
import json
import logging
import os
from os.path import join, getsize
from pathlib import Path
from pprint import pprint
import shlex
import subprocess
import sys

from blackduck.HubRestApi import HubInstance, object_id

from wait_for_scan_results import ScanMonitor

SYNOPSYS_DETECT_PATH=os.environ.get("SYNOPSYS_DETECT_PATH", "./synopsys-detect-6.5.0.jar")
DETECT_CMD=f"java -jar {SYNOPSYS_DETECT_PATH}"
FIVE_GB = 5 * 1024 * 1024 * 1024

parser = argparse.ArgumentParser("Analyze a given folder and generate one or more Synopsys Detect commands to perform SCA on the folder's contents")
parser.add_argument("bd_url", help="The Black Duck server URL, e.g. https://domain-name")
parser.add_argument("api_token", help="The Black Duck user API token")
parser.add_argument("project", help="The project name to map all the scans to")
parser.add_argument("version", help="The version name to map all the scans to")
parser.add_argument("target_dir")
parser.add_argument("-e", "--exclude_directory", action='append', help="Add a directory to the exclude list.")
parser.add_argument("-dfs", "--dont_follow_synlinks", action='store_true')
parser.add_argument("-l", "--logging_dir", help="Set the directory where Detect log files will be captured (default: current working directory)")
parser.add_argument("-s", "--size_limit", default=FIVE_GB, type=int, help="Set the size limit at which (signature) scans should be split (default: 5 GB)")
parser.add_argument("-w", "--wait", action='store_true', help="Wait for all the scan processing to complete")
parser.add_argument("-c", "--max_checks", default=240, type=int, help="When waiting for scan processing how many times to check before timing out (default: 240 for 20 minutes)")
parser.add_argument("-d", "--check_delay", default=5, type=int, help="When waiting for scan processing how long to wait before checking again (default: 5 seconds)")
parser.add_argument("-sn", "--snippet_scan", action='store_true', help="When waiting for scan processing does the scan include snippet scanning?  Note you still need to specify the Detect Properties to enable snippet scanning (default: False)")
parser.add_argument("-p", "--detect_properties", help="Provide list of (additional) detect properties (one per line) in the specified file")
args = parser.parse_args()

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

if args.detect_properties:
    logging.debug(f"Reading additional detect properties from {args.detect_properties}")
    with open(args.detect_properties, 'r') as detect_properties_f:
        additional_detect_properties = detect_properties_f.readlines()
        additional_detect_properties = [p.strip() for p in additional_detect_properties]
else:
    additional_detect_properties = []
logging.debug(f"additional detect properties: {additional_detect_properties}")

target_dir = Path(args.target_dir)
logging.debug(f"target_dir: {target_dir}")
assert os.path.isdir(target_dir), f"Target directory {target_dir} not found or does not appear to be a directory"

# TODO: Pass these through into Detect's --detect.blackduck.signature.scanner.exclusion.name.patterns option?
exclude_list = args.exclude_directory if args.exclude_directory else []
logging.debug(f"Excluding the following directory names/patterns: {exclude_list}")

directories = {}
scan_dirs = {}

def in_exclude_list(abs_path):
    return any([abs_path.match(e) for e in exclude_list])


#
# Analyze the folder tree from the bottom up
#
# If a folder exceeds the size limit, split it up by adding its sub-folders
# to the scan list. 
# Add the folder itself to the list, but exclude its sub-folders
#

exclude_folders = set()
follow_symlinks = not args.dont_follow_synlinks
logging.debug(f"Following symlinks: {follow_symlinks}")

no_splits = True

for root, subdirs, files in os.walk(target_dir, topdown=False, followlinks=follow_symlinks):
    root_path = Path(root).absolute()

    if in_exclude_list(root_path):
        exclude_folders.add(root_path)

    # TODO: if the directory we are "in" is within an excluded folder, we need to not
    # count it towards the total size?

    size = 0
    for name in files:
        try:
            size += getsize(root_path / name)
        except FileNotFoundError:
            continue
            
    if size > args.size_limit:
        logging.error(f"This folder - {root} - has files totalling {size} bytes which is greater than the limit of {args.size_limit}. We cannot split this folder any further and therefore cannot scan it. Exiting...")
        sys.exit(1)

    subdir_paths = [ root_path / d for d in subdirs]
    logging.debug(f"subdir_paths: {subdir_paths}")

    subdir_size = sum(directories.get(p, 0) for p in subdir_paths)
    my_size = directories[root_path] = size + subdir_size

    if my_size > args.size_limit:
        no_splits = False
        logging.debug(f"Splitting {root_path} cause it is {my_size} bytes which is > {args.size_limit}")
        # import pdb; pdb.set_trace()
        for subdir in subdir_paths:
            # TODO: Need to pop folders from the exclude list as we deal with them. How?
            if subdir not in scan_dirs and subdir not in exclude_folders:
                logging.debug(f"adding subdir {subdir} to list of directories to scan")
                exclude_folders_under_subdir = [f for f in exclude_folders if f.is_relative_to(subdir)]
                scan_dirs[subdir] = {"exclude_folders": exclude_folders_under_subdir}
                exclude_folders -= set(exclude_folders_under_subdir)
            else:
                logging.debug(f"subdir {subdir} is already in list of directories to scan or was in the exclude folder list, skipping")
        scan_dirs[root_path] = {"exclude_folders": subdir_paths}
    else:
        logging.debug(f"folder {root_path} with size {my_size} is under limit of {args.size_limit}")
        if root_path.is_symlink() and root_path.resolve() not in scan_dirs:
            logging.debug(f"Adding {root_path} symlink which points to {root_path.resolve()} to list of directories to scan")
            scan_dirs[root_path.resolve()] = {'exclude_folders': []}

if no_splits:
    # This means all of the directories analyzed fit within the given size limit
    # In this case we setup to run a Detect scan on the originally supplied target directory
    logging.debug(f"All of the folders within {target_dir} fit under the size limit of {args.size_limit} so adding {target_dir} to the scan directory list")
    scan_dirs[target_dir] = {"exclude_folders": exclude_folders}

logging.debug(f"scan_dirs: {scan_dirs}")

hub_instance_kwargs = {
    "api_token": args.api_token,
    "insecure": True,
    "debug": False
}

hub = HubInstance(args.bd_url, **hub_instance_kwargs) # Need a HubInstance to use the BD REST API

#
# To ensure accurate results, un-map any scans that were previously mapped to the project-version
# Failing to un-map them could result in an old scan that is no longer applicable being mapped and
# therefore including matches that don't apply anymore
#
version = hub.get_or_create_project_version(args.project, args.version)
code_locations_url = hub.get_link(version, "codelocations")
code_locations_count = 1
while code_locations_count > 0:
    code_locations = hub.execute_get(code_locations_url).json().get('items', [])
    logging.debug(f"Un-mapping code locations: {[c['name'] for c in code_locations]}")

    code_locations_count = len(code_locations)
    logging.debug(f"Code locations count {code_locations_count}")

    for code_location in code_locations:
        logging.debug(f"Unmapping code location {code_location['name']}")
        code_location['mappedProjectVersion'] = ""
        response = hub.execute_put(code_location['_meta']['href'], code_location)
        if response.status_code == 200:
            logging.debug(f"Successfully unmapped code location {code_location['name']}")
            code_location_after = hub.execute_get(code_location['_meta']['href'])
        else:
            logging.warning(f"Failed to unmap code location {code_location['name']}, status code was {response.status_code}")
    
    if code_locations_count < 10:
        code_locations_count = 0
    

#
# Run Synopsys Detect and collect the results
#
base_command = f"{DETECT_CMD} --blackduck.url={args.bd_url} --blackduck.api.token={args.api_token} --blackduck.trust.cert=true --detect.parallel.processors=-1 --detect.project.name={args.project} --detect.project.version.name={args.version}"
base_command = f"{base_command} {' '.join(additional_detect_properties)}"
logging.debug(f"base command: {base_command}")

code_locations_to_wait_for = []
start_time = arrow.utcnow()

for scan_dir, scan_dir_options in scan_dirs.items():
    exclude_folders = scan_dir_options['exclude_folders']
    exclude_folders = [e.relative_to(scan_dir) for e in exclude_folders]
    code_location = f"{args.project}-{args.version}-{scan_dir}".replace("/", "-").replace("\\", "-")
    command = f"{base_command} --detect.source.path={scan_dir} --detect.code.location.name={code_location}"
    if exclude_folders:
        # TODO: Is this the correct detect / signature scan option to use to exclude the folders?
        # TODO: Function to adjust the path information used in the detect exclusion option given the
        #   source.path (aka scan_dir) and the exclude_folders
        exclusion_name_patterns = ",".join([f"/{f}/" for f in exclude_folders])
        command = f"{command} --detect.blackduck.signature.scanner.exclusion.patterns={exclusion_name_patterns}"

    logging.debug(f"Running Synopsys detect on {scan_dir} using scan/code location name = {code_location}")
    logging.debug(f"command: {command}")
    process = subprocess.run(command, stdout=subprocess.PIPE, universal_newlines=True, shell=True)

    detect_log = f"{code_location}-detect.log"
    if args.logging_dir:
        detect_log = Path(args.logging_dir) / detect_log

    logging.debug(f"Writing detect output to {detect_log}")
    with open(detect_log, 'w') as f:
        f.write(process.stdout)

    if process.returncode == 0:
        logging.debug(f"Detect on code location {code_location} succeeded")
        code_locations_to_wait_for.append(code_location)
    else:
        logging.error(f"Detect failed with return code {process.returncode} on code location {code_location}. Look at detect log {detect_log} for more information.")

if args.wait:
    for code_location in code_locations_to_wait_for:
        logging.debug(f"Waiting for code location {code_location} to finish processing using start_time {start_time}")
        scan_monitor = ScanMonitor(hub, code_location, max_checks=args.max_checks, check_delay=args.check_delay, start_time=start_time, snippet_scan=args.snippet_scan)
        scan_status = scan_monitor.wait_for_scan_completion()
        logging.debug(f"Code location {code_location} finished with status = {scan_status}")





