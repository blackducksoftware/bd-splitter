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

SYNOPSYS_DETECT_PATH=os.environ.get("SYNOPSYS_DETECT_PATH", "/Users/gsnyder/synopsys-detect/download/synopsys-detect-6.5.0.jar")
DETECT_CMD=f"java -jar {SYNOPSYS_DETECT_PATH}"
FIVE_GB = 5 * 1024 * 1024 * 1024

default_ignore_list = ['.git']
default_ignore_list_str = ",".join(default_ignore_list)

parser = argparse.ArgumentParser("Analyze a given folder and generate one or more Synopsys Detect commands to perform SCA on the folder's contents")
parser.add_argument("bd_url", help="The Black Duck server URL, e.g. https://domain-name")
parser.add_argument("api_token", help="The Black Duck user API token")
parser.add_argument("project", help="The project name to map all the scans to")
parser.add_argument("version", help="The version name to map all the scans to")
parser.add_argument("target_dir")
parser.add_argument("-i", "--ignore_list", default=default_ignore_list_str, help=f"Comma separated list of directory names which should be ignored (default: {default_ignore_list_str})")
parser.add_argument("-l", "--logging_dir", help="Set the directory where Detect log files will be captured (default: current working directory)")
parser.add_argument("-s", "--size_limit", default=FIVE_GB, type=int, help="Set the size limit at which (signature) scans should be split (default: 5 GB)")
parser.add_argument("-w", "--wait", action='store_true', help="Wait for all the scan processing to complete")
args = parser.parse_args()

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


target_dir = Path(args.target_dir)
logging.debug(f"target_dir: {target_dir}")
assert os.path.isdir(target_dir), f"Target directory {target_dir} not found or does not appear to be a directory"

ignore_list = args.ignore_list.split(",")

directories = {}
scan_dirs = {}

#
# Analyze the folder tree from the bottom up
#
# If a folder exceeds the size limit, split it up by adding its sub-folders
# to the scan list. 
# Add the folder itself to the list, but exclude its sub-folders
#

for root, subdirs, files in os.walk(target_dir, topdown=False, followlinks=True):
    root_path = Path(root)
    size = sum(getsize(root_path / name) for name in files)
    if size > args.size_limit:
        logging.error(f"This folder - {root} - has files totalling {size} bytes which is greater than the limit of {args.size_limit}. We cannot split this folder any further and therefore cannot scan it. Exiting...")
        sys.exit(1)
    subdir_paths = [Path(root) / Path(d) for d in subdirs]
    logging.debug(f"subdir_paths: {subdir_paths}")
    subdir_size = sum(directories[p] for p in subdir_paths)
    my_size = directories[root_path] = size + subdir_size
    if my_size > args.size_limit:
        logging.debug(f"folder {root_path} with size {my_size} is over limit of {args.size_limit} so will scan subdirs ({subdirs}) separately")
        for subdir in subdirs:
            subdir_abs_path = root_path / subdir
            if subdir_abs_path in scan_dirs.keys():
                logging.debug(f"subdir {subdir_abs_path} already in list of scan_dirs, skipping...")
            elif subdir not in ignore_list:
                logging.debug(f"adding {subdir_abs_path} to scan_dirs")
                scan_dirs[subdir_abs_path] = {"exclude_folders": []}
            else:
                logging.debug(f"{subdir} subdir in  ignore_list {ignore_list} is {subdir in ignore_list}, so not adding {subdir_abs_path} to scan_dirs")
        assert root_path not in scan_dirs.keys(), f"Root {root_path} was already in scan_dirs"
        if root_path.name not in ignore_list:
            scan_dirs[root_path] = {"exclude_folders": [Path(s) for s in subdirs]}
            logging.debug(f"Adding {root_path} to scan_dirs with exclude folders = {subdirs}")
        else:
            logging.debug(f"Not adding {root_path} to scan_dirs cause it is in the ignore list")
    else:
        logging.debug(f"folder {root_path} with size {my_size} is under limit of {args.size_limit}")

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
code_locations = hub.execute_get(code_locations_url).json().get('items', [])
logging.debug(f"Un-mapping code locations: {[c['name'] for c in code_locations]}")
for code_location in code_locations:
    logging.debug(f"Unmapping code location {code_location['name']}")
    code_location['mappedProjectVersion'] = ""
    response = hub.execute_put(code_location['_meta']['href'], code_location)
    if response.status_code == 200:
        logging.debug(f"Successfully unmapped code location {code_location['name']}")
        code_location_after = hub.execute_get(code_location['_meta']['href'])
    else:
        logging.warning(f"Failed to unmap code location {code_location['name']}, status code was {response.status_code}")

#
# Run Synopsys Detect and collect the results
#
base_command = f"{DETECT_CMD} --blackduck.url={args.bd_url} --blackduck.api.token={args.api_token} --blackduck.trust.cert=true --detect.parallel.processors=-1 --detect.project.name={args.project} --detect.project.version.name={args.version}"
logging.debug(f"base command: {base_command}")

code_locations_to_wait_for = []
start_time = arrow.utcnow()

for scan_dir, scan_dir_options in scan_dirs.items():
    exclude_folders = scan_dir_options['exclude_folders']
    code_location = f"{scan_dir}-{args.project}-{args.version}".replace("/", "-").replace("\\", "-")
    command = f"{base_command} --detect.source.path={scan_dir} --detect.code.location.name={code_location}"
    if exclude_folders:
        exclusion_name_patterns = ",".join([f"/{f}/" for f in scan_dir_options['exclude_folders']])
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
        scan_monitor = ScanMonitor(hub, code_location, start_time=start_time)
        scan_status = scan_monitor.wait_for_scan_completion()
        logging.debug(f"Code location {code_location} finished with status = {scan_status}")





