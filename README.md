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

   

4. Then run bd-splitter.py 

   ```
   python3 bd-splitter.py https://bd-server-fqdn api-token project-name version-name target-dir
   ```

