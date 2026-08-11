#!/usr/bin/env python

'''

Wait for scannning results, i.e. after uploading a scan, wait for all the jobs that
process the scan results to complete

'''

import argparse
import arrow
import json
import logging
import sys
import time

# The legacy ``HubInstance`` import has been replaced with the new
# ``Client`` class, which provides ``get_resource`` (paginated generator),
# ``get_json``, and access to ``session`` for arbitrary HTTP calls.
from blackduck import Client


class ScanMonitor(object):
    SUCCESS = 0
    FAILURE = 1
    TIMED_OUT = 2

    def __init__(self, bd, scan_location_name, max_checks=10, check_delay=5, snippet_scan=False, start_time=None):
        # ``bd`` is now a blackduck.Client instance (formerly hub/HINSTANCE).
        self.bd = bd
        self.scan_location_name = scan_location_name
        self.max_checks = max_checks
        self.check_delay = check_delay
        self.snippet_scan = snippet_scan
        if not start_time:
            self.start_time = arrow.now()
        else:
            self.start_time = start_time

    @staticmethod
    def _get_link(bd_rest_obj, link_name):
        """Return the URL for ``link_name`` from a BD REST object's _meta.links.

        The new Client class no longer exposes a ``get_link`` helper, so we
        replicate it inline.
        """
        if not bd_rest_obj:
            return None
        links = bd_rest_obj.get('_meta', {}).get('links', [])
        for link in links:
            if link.get('rel') == link_name:
                return link.get('href')
        return None

    def _find_scan_locations(self):
        """Return all codelocations whose name matches this monitor's scan_location_name.

        Mirrors the old ``self.hub.get_codelocations(parameters={'q': f'name:...'})``
        call. ``get_resource`` returns an items generator that spans all pages;
        we then filter by the requested name to preserve the previous behaviour.
        """
        params = {'q': f"name:{self.scan_location_name}"}
        scan_locations = []
        # Fix: BD 2026.4.0 API exposes 'codeLocations' (camelCase), not
        # 'codelocations'. The blackduck Client's get_resource validates the
        # resource name against the live API resource map and raises
        # KeyError on mismatch, which used to crash -w mode entirely.
        for codelocation in self.bd.get_resource('codeLocations', params=params):
            if codelocation.get('name') == self.scan_location_name:
                scan_locations.append(codelocation)
        return scan_locations

    def wait_for_scan_completion(self):
        scan_locations = self._find_scan_locations()
        logging.debug(f"Scan locations found: {len(scan_locations)}")

        remaining_checks = self.max_checks

        while remaining_checks > 0:

            for scan_location in scan_locations:

                scans_url = self._get_link(scan_location, "scans")

                # ``get_json`` returns the parsed dict directly; no need to
                # call ``.json()`` again like we used to on the response object.
                scans_json = self.bd.get_json(scans_url) if scans_url else {}
                scans = scans_json.get('items', [])

                newer_scans = list(filter(lambda s: arrow.get(s['updatedAt']) > self.start_time, scans))

                if (len(newer_scans) > 0):
                    if len(newer_scans) > 0 and self.snippet_scan:
                        # We are snippet scanning, we need to check if we should be waiting for another scan.  Only the case if one of them is FS or if one is SNIPPET.  If one is BDIO then it will not have snippet.
                        fs_scans = list(filter(lambda s: s['scanType'] == 'FS', newer_scans))
                        snippet_scans = list(filter(lambda s: s['scanType'] == 'SNIPPET', newer_scans))
                        if len(fs_scans) > 0 or len(snippet_scans) > 0:
                            # This is a candicate for snippet scan
                            expected_scans_seen = len(fs_scans) > 0 and len(snippet_scans) > 0
                            logging.debug(f"Snippet scanning - candidate code location - newer scans {len(newer_scans)}, expected_scans_seen: {expected_scans_seen} for {scan_location['name']}")
                        else:
                            # This is another type of scan.
                            expected_scans_seen = True
                            logging.debug(f"Snippet scanning - non snippet code location - newer scans {len(newer_scans)}, expected_scans_seen: {expected_scans_seen} for {scan_location['name']}")

                    else:
                        # We have one or more newer scans
                        expected_scans_seen = True
                        logging.debug(f"Not Snippet scanning - newer scans {len(newer_scans)}, expected_scans_seen: {expected_scans_seen} for {scan_location['name']}")
                else:
                    logging.debug(f"No newer scans found for {scan_location['name']}")
                    expected_scans_seen = False

                if expected_scans_seen and all([s['status'] in ['COMPLETE', 'FAILURE'] for s in newer_scans]):
                    logging.info(f"Scans have finished processing for {scan_location['name']}")
                    if all([s['status'] == 'COMPLETE' for s in newer_scans]):
                        # All scans for this code location are complete, remove from the list we are waiting on.
                        scan_locations.remove(scan_location)
                    else:
                        return ScanMonitor.FAILURE

            if len(scan_locations) == 0:
                # All code locations are complete.
                return ScanMonitor.SUCCESS

            remaining_checks -= 1
            logging.info(f"Waiting for {len(scan_locations)} code locations.  Sleeping for {self.check_delay} seconds before checking again. {remaining_checks} remaining")
            time.sleep(self.check_delay)

        return ScanMonitor.TIMED_OUT


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Wait for scan processing to complete for a given code (scan) location/name and provide an exit status - 0 successful, 1 failed, and 2 timed-out")
    parser.add_argument("scan_location_name", help="The scan location name")
    parser.add_argument('-m', '--max_checks', type=int, default=10, help="Set the maximum number of checks before quitting")
    parser.add_argument('-t', '--time_between_checks', type=int, default=5, help="Set the number of seconds to wait in-between checks")
    parser.add_argument('-s', '--snippet_scan', action='store_true', help="Select this option if you want to wait for a snippet scan to complete along with it's corresponding component scan.")
    parser.add_argument('-u', '--base-url', required=True, help="Hub server URL e.g. https://your.blackduck.url")
    parser.add_argument('-tkn', '--token-file', dest='token_file', required=True, help="File containing access token")
    parser.add_argument('-nv', '--no-verify', dest='verify', action='store_false', help="Disable TLS certificate verification")
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("blackduck").setLevel(logging.WARNING)

    with open(args.token_file, 'r') as tf:
        access_token = tf.readline().strip()

    bd = Client(
        base_url=args.base_url,
        token=access_token,
        verify=args.verify,
        timeout=30.0,
        retries=3,
    )

    scan_monitor = ScanMonitor(bd, args.scan_location_name, args.max_checks, args.time_between_checks, args.snippet_scan)
    scan_monitor.wait_for_scan_completion()
