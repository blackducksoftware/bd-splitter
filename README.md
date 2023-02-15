# Black Duck Scanning Splitter

Black Duck has a per-scan limit of 5 GB (on signature scans) to protect server resources from being overloaded and to encourage splitting up large projects into multiple, smaller scans that allow results to be produced faster and with less overhead. Customers want a solution that automates the splitting of a large project into smaller scans.

This repository provides a python-based example that will split the targeted folder/directory into (signature) scans that will fit within the size limit.

### Requirements

- python3
- Install dependencies specified in *requirements.txt*
- Black Duck server URL
- BD user API token
- Synopsys Detect jar
  - a version of Synopsys detect jar is included in this repository

### How to Run

1. Install the dependencies for bd-splitter into your (virtual) environment 

   ```
   pip3 install -r requirements.txt 
   ```

   

4. Create .restconfig.json file with the required BD URL, BD user API token.

3. Then run bd-splitter.py 

   ```
   python3 bd-splitter.py --bd_url <https://bd-server-fqdn> --api_token <api-token> --project <project-name> --version <version-name> --target_dir <target-dir>
   ```

# Release Log

- Nov 2, 2020
  - Tag/version 1.0.1
    - Add try/except to overcome FileNotFoundError resulting from symbolic link to a file that no longer exists