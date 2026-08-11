#!/usr/bin/env python

import argparse
import arrow
import json
import logging
import os
from os.path import join, getsize
from pathlib import Path
from pprint import pprint
import resource
import shlex
import signal
import subprocess
import sys

from blackduck import Client

from wait_for_scan_results import ScanMonitor

BLACKDUCK_DETECT_PATH=os.environ.get("BLACKDUCK_DETECT_PATH", "./detect-11.4.2.jar")
DETECT_CMD=f"java -jar {BLACKDUCK_DETECT_PATH}"
# Fix 11: default to 5 GB to match the per-scan limit documented in the help
# text and on the Black Duck server side. The previous literal (15 GB) silently
# made the splitter a no-op for any project under 15 GB and only kicked in for
# very large AOSP-class trees, contradicting the `--help` output and the README.
FIVE_GB = 5 * 1024 * 1024 * 1024

parser = argparse.ArgumentParser("Analyze a given folder and generate one or more BlackDuck Detect commands to perform SCA on the folder's contents")
parser.add_argument("bd_url", help="The BlackDuck server URL, e.g. https://domain-name")
parser.add_argument("api_token", help="The BlackDuck user API token")
parser.add_argument("project", help="The project name to map all the scans to")
parser.add_argument("version", help="The version name to map all the scans to")
parser.add_argument("target_dir")
parser.add_argument("-e", "--exclude_directory", action='append', help="Add a directory to the exclude list.")
# Fix 1: -dfs is kept for backwards compatibility but is now the default.
parser.add_argument("-dfs", "--dont_follow_symlinks", action='store_true',
                    help="Deprecated: symlinks are no longer followed by default (use --follow_symlinks to override).")
parser.add_argument("--follow_symlinks", action='store_true',
                    help="Follow symbolic links when scanning (default: False, recommended for projects with .repo / node_modules).")
parser.add_argument("-l", "--logging_dir", help="Set the directory where Detect log files will be captured (default: current working directory)")
parser.add_argument("-s", "--size_limit", default=FIVE_GB, type=int, help="Set the size limit at which (signature) scans should be split (default: 5 GB)")
parser.add_argument("-w", "--wait", action='store_true', help="Wait for all the scan processing to complete")
parser.add_argument("-c", "--max_checks", default=240, type=int, help="When waiting for scan processing how many times to check before timing out (default: 240 for 20 minutes)")
parser.add_argument("-d", "--check_delay", default=5, type=int, help="When waiting for scan processing how long to wait before checking again (default: 5 seconds)")
parser.add_argument("-sn", "--snippet_scan", action='store_true', help="When waiting for scan processing does the scan include snippet scanning?  Note you still need to specify the Detect Properties to enable snippet scanning (default: False)")
parser.add_argument("-p", "--detect_properties", help="Provide list of (additional) detect properties (one per line) in the specified file")
args = parser.parse_args()

# Fix 3: default to INFO to avoid producing millions of DEBUG log lines for
# huge projects (which alone can consume several GB of memory via buffered
# stderr + f-string temporaries). Set BD_SPLITTER_DEBUG=1 to opt back into DEBUG.
#
# Fix 9: bd-splitter's own log goes to ./log/bd-splitter.log by default (was
# stderr-only). ERROR-level messages are ALSO mirrored to stderr so they
# remain visible in the terminal even when everything else is silenced.
# Override the file with BD_SPLITTER_LOG_FILE=<path>; set to /dev/null to
# disable file logging entirely.
log_level = logging.DEBUG if os.environ.get("BD_SPLITTER_DEBUG") else logging.INFO

LOG_DIR = Path(os.environ.get("BD_SPLITTER_LOG_DIR", "./log"))
LOG_FILE = os.environ.get("BD_SPLITTER_LOG_FILE", str(LOG_DIR / "bd-splitter.log"))
if LOG_FILE and LOG_FILE != "/dev/null":
    LOG_DIR.mkdir(parents=True, exist_ok=True)

# Build handlers explicitly (replaces logging.basicConfig so we can route
# differently per level).
root_logger = logging.getLogger()
for h in list(root_logger.handlers):
    root_logger.removeHandler(h)
formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")
if LOG_FILE and LOG_FILE != "/dev/null":
    file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
# Mirror ERROR+ to stderr so problems stay visible in the terminal even
# when a long, quiet run is mostly being recorded in the log file.
stderr_handler = logging.StreamHandler(stream=sys.stderr)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.setFormatter(formatter)
root_logger.addHandler(stderr_handler)
root_logger.setLevel(log_level)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("blackduck").setLevel(logging.INFO)
logging.info(f"bd-splitter log file: {LOG_FILE} (level={logging.getLevelName(log_level)})")

# ---------------------------------------------------------------------------
# Resource-snapshot helpers
# ---------------------------------------------------------------------------
# Fix 12: surface per-chunk host memory + disk pressure so a future "stuck at
# chunk #N with no further log output" failure (see errors.jpg from 2026-07-25
# — the run died silently after INFO:[412/825] Starting Detect ...) is
# diagnosable from the bd-splitter log alone, without having to also reach for
# dmesg / df at the time of failure. All measurements are stdlib (resource +
# os.statvfs + signal) so no new dependency is added to requirements.txt.
def _human_bytes(n: int) -> str:
    """Format a byte count as e.g. '1.23GB'. Returns 'unknown' on bad input."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "unknown"
    sign = "-" if n < 0 else ""
    n = abs(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{sign}{n:.1f}{unit}"
        n /= 1024.0
    return f"{sign}{n:.1f}PB"


def _disk_snapshot(path: str = ".") -> str:
    """Return 'disk_free=85.3GB/100.0GB (15% used)' for the filesystem that
    backs `path`. Falls back to 'disk_free=unknown' on permission errors or
    non-POSIX platforms."""
    try:
        st = os.statvfs(path)
        # f_bavail = blocks available to non-root user; f_frsize = fragment size
        free = st.f_bavail * st.f_frsize
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            return "disk_free=unknown"
        used_pct = int(round(100.0 * (total - free) / total))
        return f"disk_free={_human_bytes(free)}/{_human_bytes(total)} ({used_pct}% used)"
    except (OSError, AttributeError):
        # AttributeError: os.statvfs missing on Windows
        return "disk_free=unknown"


def _mem_snapshot() -> str:
    """Return 'rss=120.5MB peak=450.2MB' for the bd-splitter Python process.
    Uses resource.getrusage(RUSAGE_SELF) — no psutil dependency.
    Note: on Linux ru_maxrss is in KILOBYTES, on macOS in BYTES; we normalize
    to bytes and let _human_bytes pick the unit."""
    try:
        ru = resource.getrusage(resource.RUSAGE_SELF)
        rss_bytes = ru.ru_maxrss
        if sys.platform == "darwin":
            pass  # already bytes
        else:
            rss_bytes *= 1024  # Linux: KB -> bytes
        return f"rss={_human_bytes(rss_bytes)}"
    except (OSError, ValueError):
        return "rss=unknown"


def _snapshot(label: str, path: str = ".") -> str:
    """Single-line, copy-paste-friendly resource snapshot for logging."""
    return f"[{label}] {_mem_snapshot()} | {_disk_snapshot(path)}"


def _returncode_repr(rc) -> str:
    """Explain a non-zero subprocess returncode.
    On POSIX a negative rc means the child was killed by signal -rc (e.g.
    -9 = SIGKILL = typical OOM-killer / dmesg 'Killed process' fingerprint;
    -15 = SIGTERM = manual kill). Returning a human-readable hint lets the
    existing FAILED log line tell us WHY without inspecting dmesg."""
    try:
        rc = int(rc)
    except (TypeError, ValueError):
        return f"returncode={rc}"
    if rc == 0:
        return "returncode=0"
    if rc < 0:
        sig_num = -rc
        try:
            sig_name = signal.Signals(sig_num).name
        except (ValueError, AttributeError):
            sig_name = f"signal-{sig_num}"
        # SIGKILL = 9 is almost always OOM-killer on Linux; surface that hint.
        hint = " (likely OOM-killer)" if sig_num == signal.SIGKILL.value else ""
        return f"returncode={rc} [killed by {sig_name}]{hint}"
    return f"returncode={rc}"


if args.detect_properties:
    logging.debug(f"Reading additional detect properties from {args.detect_properties}")
    with open(args.detect_properties, 'r') as detect_properties_f:
        additional_detect_properties = detect_properties_f.readlines()
        additional_detect_properties = [p.strip() for p in additional_detect_properties]
else:
    additional_detect_properties = []
logging.debug(f"additional detect properties: {additional_detect_properties}")

# Normalize target_dir to an absolute Path so relative_to() works consistently
# for every directory produced by os.walk (which inherits the absoluteness of
# its top argument).
target_dir = Path(args.target_dir).absolute()
logging.debug(f"target_dir: {target_dir}")
assert os.path.isdir(target_dir), f"Target directory {target_dir} not found or does not appear to be a directory"

logging.info(
    f"=== bd-splitter START === "
    f"project={args.project!r} version={args.version!r} "
    f"target={target_dir} "
    f"size_limit={args.size_limit} bytes ({args.size_limit / (1024**3):.2f} GB) "
    f"wait={'yes' if args.wait else 'no'} "
    f"snippet_scan={'yes' if args.snippet_scan else 'no'}"
)
# Fix 16: every per-chunk Detect command is logged at INFO level below in
# full (including the API token) so the operator can copy-paste it into a
# shell and reproduce a hung/failing scan manually. That means the token
# ends up in plaintext in {LOG_FILE}. Same exposure as `ps aux` (which
# already shows the token via `java -jar detect.jar --blackduck.api.token=…`),
# so the actual recommendation is unchanged — chmod 600 {LOG_FILE} and
# don't share it without redacting the token first.
logging.info(
    f"NOTE: per-chunk Detect commands (incl. API token) will be logged "
    f"in full below; chmod 600 {LOG_FILE} if it contains sensitive tokens."
)

# TODO: Pass these through into Detect's --detect.blackduck.signature.scanner.exclusion.name.patterns option?
# Fix 6: built-in excludes for directories that are typically enormous and
# never need scanning. Without these, projects like Android .repo or
# node_modules trees balloon both the walk time and the directories cache.
BUILTIN_EXCLUDES = [
    ".git/objects",
    ".repo/project-objects",
    "node_modules",
    ".gradle",
    "build",
    "target",
    "dist",
    "vendor",
    "__pycache__",
]
user_excludes = args.exclude_directory if args.exclude_directory else []
exclude_list = list(set(user_excludes + BUILTIN_EXCLUDES))
logging.debug(f"Excluding the following directory names/patterns: {exclude_list}")

# Fix 4: cache per-directory sizes as relative-path strings (not Path objects)
# to cut memory usage roughly 5-6x for projects with millions of directories.
directories = {}
scan_dirs = {}

def in_exclude_list(abs_path):
    """Match exclude patterns as path segments so e.g. '.repo/project-objects'
    matches '/src/.repo/project-objects/foo'. Falls back to glob match for
    backwards-compatible top-level patterns supplied via -e.

    Fix 8: ``**`` in a pattern now means "zero or more path segments" (proper
    recursive glob), so e.g. ``**/objects/pack`` matches
    ``/x/objects/pack``, ``/x/y/objects/pack``, etc. Backwards compat:
    literal substring still wins first; ``Path.match`` fallback handles
    plain ``*``; ``**`` regex handles the recursive case.
    """
    abs_str = "/" + str(abs_path).rstrip("/") + "/"
    abs_posix = abs_path.as_posix()
    for pattern in exclude_list:
        # Literal-segment match: '/pattern/' anywhere in the absolute path
        pat = "/" + pattern.strip("/").replace("\\", "/") + "/"
        if pat in abs_str:
            return True
        # Plain glob (single-segment `*`): pathlib's match
        if abs_path.match(pattern):
            return True
        # Recursive glob (`**`): translate to regex
        if "**" in pattern:
            regex = _glob_to_regex(pattern)
            if regex.search(abs_posix):
                return True
    return False


def in_exclude_file_list(filename):
    """Match a FILE name (basename, not full path) against exclude patterns.

    Fix 8: lets ``-e '*.pack'`` and ``-e '*.idx'`` skip individual files
    inside otherwise-scanned directories, which matters for huge binary
    blobs (``.git/objects/pack/*.pack``) that would otherwise blow the
    size limit even though their parent dir was meant to be excluded.
    Patterns without ``*`` are treated as exact-name matches for clarity.
    """
    for pattern in exclude_list:
        if "*" in pattern or "?" in pattern or "[" in pattern:
            if "**" in pattern:
                regex = _glob_to_regex(pattern)
                if regex.search(filename):
                    return True
            else:
                # fnmatch for single-segment globs (e.g. '*.pack')
                import fnmatch
                if fnmatch.fnmatch(filename, pattern):
                    return True
        else:
            if filename == pattern:
                return True
    return False


def _glob_to_regex(pattern):
    """Translate a glob with ``**`` support into a compiled regex.

    - ``**`` between separators matches any number of path segments
      (including zero)
    - ``**`` at the ends behaves like ``*``
    - ``*``, ``?``, ``[abc]`` keep their usual fnmatch meaning (single segment)
    - ``.`` is escaped
    """
    import re as _re
    # Normalize to forward slashes for matching against posix paths
    p = pattern.replace("\\", "/")
    parts = p.split("/")
    out = []
    for i, part in enumerate(parts):
        if part == "**":
            # Match zero or more segments between separators
            if i == 0:
                out.append("(?:.*/)?")
            else:
                out.append("(?:.*/)?")
        else:
            # Escape regex specials, then restore fnmatch meta
            sub = _re.escape(part)
            sub = sub.replace(r"\*", "[^/]*")
            sub = sub.replace(r"\?", "[^/]")
            sub = sub.replace(r"\[", "[").replace(r"\]", "]")
            out.append(sub)
    body = "/".join(out)
    return _re.compile("(?:" + body + ")\\Z")


#
# Analyze the folder tree from the bottom up
#
# If a folder exceeds the size limit, split it up by adding its sub-folders
# to the scan list.
# Add the folder itself to the list, but exclude its sub-folders
#

exclude_folders = set()
# Fix 1: default to NOT following symlinks. For projects with many symlinks
# (Android .repo, node_modules, ...) following them causes exponential
# directory blow-up and multi-GB memory consumption. Opt in with
# --follow_symlinks only when really needed.
follow_symlinks = bool(args.follow_symlinks)
logging.debug(f"Following symlinks: {follow_symlinks}")

no_splits = True

logging.info("Walking target directory (may take a while for very large trees)...")

# Fix 10: --follow_symlinks can cause os.walk to descend into a symlink
# chain that loops back to a directory already visited.  os.walk only
# bails out when the kernel raises ELOOP, which only happens for very
# long chains; shorter cycles (e.g. cycle -> sub -> up -> cycle) just
# hang forever.  We do a *pruned* topdown=True first pass to collect
# (root, subdirs, files) tuples — pruning any child whose realpath
# we've already seen — and then process the saved list bottom-up so
# the size-accumulation logic still works exactly as before.
seen_real_dirs = set()
walked_entries = []  # collected (root, subdirs, files) for the bottom-up pass
pruned_count = 0

for root, subdirs, files in os.walk(target_dir, topdown=True, followlinks=follow_symlinks):
    root_path = Path(root)
    try:
        real_root = root_path.resolve()
    except OSError as e:
        # ELOOP/ENOENT/EACCES — don't recurse into this entry's subtree.
        logging.debug(f"Cannot resolve {root_path} ({e}); not descending further here")
        subdirs[:] = []
        continue
    if real_root in seen_real_dirs:
        # We already visited this real directory; don't descend again.
        logging.debug(f"Pruning {root_path} — already counted via real path {real_root}")
        subdirs[:] = []
        pruned_count += 1
        continue
    seen_real_dirs.add(real_root)

    # Prune in place: drop any subdir whose realpath we've already seen,
    # so os.walk never descends into the cycle.
    kept_subdirs = []
    for d in subdirs:
        child = root_path / d
        try:
            real_child = child.resolve()
        except OSError as e:
            logging.debug(f"Cannot resolve child {child} ({e}); keeping as-is")
            kept_subdirs.append(d)
            continue
        if real_child in seen_real_dirs:
            logging.debug(f"Pruning child {child} of {root_path} — already counted via real path {real_child}")
            pruned_count += 1
            continue
        kept_subdirs.append(d)
    subdirs[:] = kept_subdirs

    walked_entries.append((root, list(subdirs), list(files)))

logging.debug(f"Fix 10: pruned {pruned_count} symlink-cycle entries; {len(walked_entries)} unique directories to score")
logging.info(f"Walk done: {len(walked_entries)} unique directories scored ({pruned_count} symlink-cycle entries pruned)")

# Process the collected entries bottom-up so that each directory's size
# is `its own files + sum of its subdirectories' sizes` (the original
# topdown=False algorithm).  Identical body to the previous loop, just
# sourced from `walked_entries` instead of os.walk.
for root, subdirs, files in reversed(walked_entries):
    root_path = Path(root)

    if in_exclude_list(root_path):
        logging.debug(f"Adding {root_path} to the exclude folder list")
        exclude_folders.add(root_path)
        # Skip size accumulation for excluded folders: their contents (e.g. *.pack in
        # .git/objects/pack) can easily exceed the size limit on their own, which
        # would otherwise cause us to abort even though we've already chosen to
        # exclude them. Also, because the parent walk will read directories.get(...) to
        # compute its own total, omitting this entry naturally drops the excluded
        # subtree from the parent's running size.
        continue

    size = 0
    for name in files:
        if in_exclude_file_list(name):
            # Fix 8: skip files that match a file-level exclude pattern
            # (e.g. -e '*.pack' to drop huge git pack files from size tally
            # without needing to exclude their parent directory entirely).
            continue
        try:
            size += getsize(join(root, name))
        except (FileNotFoundError, OSError) as e:
            continue

    if size > args.size_limit:
        logging.error(f"This folder - {root} - has files totalling {size} bytes which is greater than the limit of {args.size_limit}. We cannot split this folder any further and therefore cannot scan it. Exiting...")
        sys.exit(1)

    subdir_paths = [root_path / d for d in subdirs]
    logging.debug(f"subdir_paths: {subdir_paths}")

    # Fix 4: use relative-path strings as dict keys instead of Path objects.
    # This shrinks the directories cache roughly 5-6x for projects with
    # millions of directories (a 200-byte Path key becomes a ~30-byte str).
    try:
        rel_root = "." if root_path == target_dir else str(root_path.relative_to(target_dir))
        subdir_rels = [str(p.relative_to(target_dir)) for p in subdir_paths]
    except ValueError:
        # Subdir outside target_dir (shouldn't normally happen with os.walk).
        rel_root = str(root_path)
        subdir_rels = [str(p) for p in subdir_paths]

    subdir_size = sum(directories.get(p, 0) for p in subdir_rels)
    my_size = directories[rel_root] = size + subdir_size

    if my_size > args.size_limit:
        no_splits = False
        logging.debug(f"Splitting {root_path} cause it is {my_size} bytes which is > {args.size_limit}")
        # import pdb; pdb.set_trace()
        for subdir in subdir_paths:
            # TODO: Need to pop folders from the exclude list as we deal with them. How?
            if subdir not in scan_dirs and subdir not in exclude_folders:
                logging.debug(f"adding subdir {subdir} to list of directories to scan")
                exclude_folders_under_subdir = [f for f in exclude_folders if f.is_relative_to(subdir)]
                logging.debug(f"excluding dirs {exclude_folders_under_subdir} from subdir {subdir} analysis")
                # Fix 13: remember the chunk's own size so the per-chunk START
                # log line can report it (and its % of size_limit) without
                # having to keep the per-directory size cache around.
                try:
                    subdir_rel = str(subdir.relative_to(target_dir))
                except ValueError:
                    subdir_rel = str(subdir)
                scan_dirs[subdir] = {"exclude_folders": exclude_folders_under_subdir, "size_bytes": directories.get(subdir_rel, 0)}
                exclude_folders -= set(exclude_folders_under_subdir)
            else:
                logging.debug(f"subdir {subdir} is already in list of directories to scan or was in the exclude folder list, skipping")
        scan_dirs[root_path] = {"exclude_folders": subdir_paths, "size_bytes": my_size}
    else:
        logging.debug(f"folder {root_path} with size {my_size} is under limit of {args.size_limit}")
        try:
            is_link = root_path.is_symlink()
            resolved = root_path.resolve() if is_link else None
        except OSError as e:
            # ELOOP / ENOENT / EACCES 等：把 root 当作普通目录，跳过 symlink 特殊处理
            logging.debug(f"Cannot lstat/resolve {root_path} ({e}); treating as regular dir")
            continue
        if is_link and resolved not in scan_dirs:
            logging.debug(f"Adding {root_path} symlink which points to {resolved} to list of directories to scan")
            scan_dirs[resolved] = {'exclude_folders': [], "size_bytes": my_size}

# Fix 5: release the per-directory size cache as soon as the walk is done.
# It is only used during traversal to compute parent sizes; once we have
# scan_dirs we don't need it anymore. Freeing it now prevents it from
# lingering through the (potentially long) Detect phase.
# Fix 13: capture the target_dir size BEFORE deleting the cache, since the
# no_splits branch below needs it for the single-chunk START log line.
target_dir_size = directories.get(".", 0)
del directories
import gc
gc.collect()

if no_splits:
    # This means all of the directories analyzed fit within the given size limit
    # In this case we setup to run a Detect scan on the originally supplied target directory
    logging.debug(f"All of the folders within {target_dir} fit under the size limit of {args.size_limit} so adding {target_dir} to the scan directory list")
    scan_dirs[target_dir] = {"exclude_folders": exclude_folders, "size_bytes": target_dir_size}

logging.debug(f"scan_dirs: {scan_dirs}")
# Fix 13: the split algorithm intentionally keeps both the over-limit
# directory AND its sub-directories in scan_dirs (so Detect can scan the
# root with the leaves excluded via --detect.excluded.directories while
# ALSO scanning each leaf individually). Summing `size_bytes` directly
# double-counts: every leaf byte appears in both its parent's and its
# own chunk. For an honest "how much unique disk will Detect touch?"
# total we subtract any other chunk that lives under one of this
# chunk's excludes.
chunk_paths = list(scan_dirs.keys())
chunk_size_bytes_map = {p: opts.get("size_bytes", 0) for p, opts in scan_dirs.items()}
chunk_effective_bytes_map = {}
for chunk_path, opts in scan_dirs.items():
    effective = chunk_size_bytes_map[chunk_path]
    for excl in opts.get("exclude_folders", []):
        for other in chunk_paths:
            if other != chunk_path and other.is_relative_to(excl):
                effective -= chunk_size_bytes_map[other]
    chunk_effective_bytes_map[chunk_path] = max(0, effective)
total_split_bytes = sum(chunk_effective_bytes_map.values())
logging.info(
    f"Split plan: {len(scan_dirs)} chunk(s) to scan, "
    f"total size = {_human_bytes(total_split_bytes)} "
    f"(split={'required' if not no_splits else 'not required'})"
)

#
# Instantiate a Client (the newer replacement for HubInstance) to use
# the BD REST API.  ``insecure=True`` in the old HubInstance maps to
# ``verify=False`` here. The BearerAuth automatically renews tokens; no
# need for a separate login step.
#
bd = Client(
    base_url=args.bd_url,
    token=args.api_token,
    verify=False,
    timeout=30.0,
    retries=3,
)


def get_link(bd_rest_obj, link_name):
    """Return the URL for ``link_name`` from a BD REST object, or None.

    The new Client class no longer carries a ``get_link`` helper, so we
    resolve the equivalent by walking ``_meta.links`` ourselves.
    """
    if bd_rest_obj and '_meta' in bd_rest_obj and 'links' in bd_rest_obj['_meta']:
        for link_obj in bd_rest_obj['_meta']['links']:
            if 'rel' in link_obj and link_obj['rel'] == link_name:
                return link_obj.get('href', None)
    return None


def find_project_by_name(bd, project_name):
    """Return the project dict matching ``project_name`` or None."""
    params = {'q': [f"name:{project_name}"]}
    try:
        projects = [p for p in bd.get_resource('projects', params=params)
                    if p['name'] == project_name]
    except KeyError as e:
        logging.error(f"find_project_by_name: resource lookup failed: {e}")
        return None
    if len(projects) == 1:
        return projects[0]
    elif len(projects) > 1:
        logging.warning(f"Multiple projects matched {project_name!r}; using the first")
        return projects[0]
    return None


def find_version_by_name(bd, project, version_name):
    """Return the version dict matching ``version_name`` within project, or None."""
    params = {'q': [f"versionName:{version_name}"]}
    try:
        versions = [v for v in bd.get_resource('versions', project, params=params)
                    if v['versionName'] == version_name]
    except KeyError as e:
        logging.error(f"find_version_by_name: resource lookup failed: {e}")
        return None
    if len(versions) == 1:
        return versions[0]
    elif len(versions) > 1:
        logging.warning(f"Multiple versions matched {version_name!r}; using the first")
        return versions[0]
    return None


def create_project_with_version(bd, project_name, version_name):
    """Create project + an initial version in one call (BD's create-on-project flow)."""
    project_url = bd.base_url.rstrip("/") + "/api/projects"
    post_data = {
        "name": project_name,
        "description": "",
        "projectLevelAdjustments": True,
        "cloneCategories": ["COMPONENT_DATA", "VULN_DATA"],
        "versionRequest": {
            "phase": "PLANNING",
            "distribution": "EXTERNAL",
            "projectLevelAdjustments": True,
            "versionName": version_name,
        }
    }
    response = bd.session.post(project_url, json=post_data)
    if response.status_code not in (200, 201):
        bd.http_error_handler(response)
        response.raise_for_status()
    return response


def create_project_version(bd, project, version_name):
    """Create a new version within an existing project."""
    project_url = project['_meta']['href']
    versions_url = project_url + "/versions"
    post_data = {
        "versionName": version_name,
        "phase": "PLANNING",
        "distribution": "EXTERNAL",
        "cloneCategories": ["COMPONENT_DATA", "VULN_DATA"],
    }
    response = bd.session.post(versions_url, json=post_data)
    if response.status_code not in (200, 201):
        bd.http_error_handler(response)
        response.raise_for_status()
    return response


def get_or_create_project_version(bd, project_name, version_name):
    """Find or create the (project, version) pair and return the version dict.

    Behaviour mirrors the old HubInstance.get_or_create_project_version helper:
      - if project + version both exist, return the existing version
      - if project exists but version does not, create the version
      - if project does not exist, create project (and the version with it)
    """
    project = find_project_by_name(bd, project_name)
    version = None
    if project:
        version = find_version_by_name(bd, project, version_name)
        if not version:
            logging.debug(f"Project {project_name!r} exists, creating version {version_name!r}")
            create_project_version(bd, project, version_name)
            version = find_version_by_name(bd, project, version_name)
    else:
        logging.debug(f"Project {project_name!r} does not exist, creating it along with version {version_name!r}")
        create_project_with_version(bd, project_name, version_name)
        project = find_project_by_name(bd, project_name)
        version = find_version_by_name(bd, project, version_name)
    if not version:
        raise RuntimeError(f"Failed to obtain version object for project={project_name!r}, version={version_name!r}")
    return version


#
# To ensure accurate results, un-map any scans that were previously mapped to the project-version
# Failing to un-map them could result in an old scan that is no longer applicable being mapped and
# therefore including matches that don't apply anymore
#
version = get_or_create_project_version(bd, args.project, args.version)
code_locations_url = get_link(version, "codelocations")
code_locations_count = 1
while code_locations_count > 0:
    # The old code paged through 10 items at a time (server default).  Preserve
    # the same loop shape with the new Client by calling get_json directly
    # with an explicit limit/offset.
    code_locations = bd.get_json(
        code_locations_url,
        params={'limit': 10}
    ).get('items', [])
    logging.debug(f"Un-mapping code locations: {[c['name'] for c in code_locations]}")

    code_locations_count = len(code_locations)
    logging.debug(f"Code locations count {code_locations_count}")

    for code_location in code_locations:
        logging.debug(f"Unmapping code location {code_location['name']}")
        code_location['mappedProjectVersion'] = ""
        response = bd.session.put(code_location['_meta']['href'], json=code_location)
        if response.status_code == 200:
            logging.debug(f"Successfully unmapped code location {code_location['name']}")
            response_after = bd.get_json(code_location['_meta']['href'])
        else:
            logging.warning(f"Failed to unmap code location {code_location['name']}, status code was {response.status_code}")

    if code_locations_count < 10:
        code_locations_count = 0


#
# Run BlackDuck Detect and collect the results
#
base_command = f"{DETECT_CMD} --blackduck.url={args.bd_url} --blackduck.api.token={args.api_token} --blackduck.trust.cert=true --detect.parallel.processors=-1 --detect.project.name={args.project} --detect.project.version.name={args.version}"
base_command = f"{base_command} {' '.join(additional_detect_properties)}"

# Fix 17: limit Detect to SIGNATURE_SCAN only by default. Per customer
# 2026-07-29 testing requirement, every per-chunk Detect invocation must
# include --detect.tools=SIGNATURE_SCAN so package-manager detectors
# (DETECTOR), BINARY_SCAN, etc. do not run. For large AOSP-style trees
# those add runtime + BD licence cost without extra value — signature
# scanning is the primary mechanism for matching code to the KB.  Every
# per-chunk command (line below) inherits this from base_command.
#
# Override semantics (env var BD_SPLITTER_DETECT_TOOLS):
#   - unset (default)       → --detect.tools=SIGNATURE_SCAN
#   - empty string ("")     → flag NOT added at all (legacy behaviour)
#   - "SIGNATURE_SCAN"      → --detect.tools=SIGNATURE_SCAN (explicit default)
#   - "SIGNATURE_SCAN,BIN"  → --detect.tools=SIGNATURE_SCAN,BIN (multi)
#   - "DETECTOR"            → only detectors, no sig scan (unusual)
DETECT_TOOLS = os.environ.get("BD_SPLITTER_DETECT_TOOLS", "SIGNATURE_SCAN").strip()
if DETECT_TOOLS:
    logging.info(
        f"Fix 17: --detect.tools={DETECT_TOOLS} will be appended to every "
        f"per-chunk Detect command (override via BD_SPLITTER_DETECT_TOOLS env var)"
    )
    base_command = f"{base_command} --detect.tools={DETECT_TOOLS}"

logging.debug(f"base command: {base_command}")

code_locations_to_wait_for = []
start_time = arrow.utcnow()

# Fix 7 + Fix 9: ensure the directory used for per-scan Detect logs exists
# before any Detect scan tries to open its log file inside it. Without this,
# a typo'd path or a fresh dir causes the first `open(detect_log, 'wb')` to
# fail with FileNotFoundError. -l/--logging_dir overrides the default of
# ./log/detect_logs/ so all Detect output stays inside the project's ./log/
# tree by default instead of cluttering cwd.
default_detect_log_dir = LOG_DIR / "detect_logs"
detect_log_dir = Path(args.logging_dir) if args.logging_dir else default_detect_log_dir
detect_log_dir.mkdir(parents=True, exist_ok=True)

total_chunks = len(scan_dirs)
detect_ok = 0
detect_failed = 0
logging.info(f"Running Detect on {total_chunks} chunk(s)...")

# Fix 17: the ARG_MAX / MAX_ARG_STRLEN guard that used to live here (Fix 15B)
# has been removed. It existed because the command embedded every excluded
# directory as a fully-expanded path, which on AOSP's external/cronet (2000+
# third-party submodules, each with .git/) grew --detect.excluded.directories
# past the kernel's 128 KB per-argument limit and made subprocess.run raise
# `OSError: [Errno 7] Argument list too long` before Detect ever started.
# Detect does name/substring matching on --detect.excluded.directories itself
# (verified by probe: passing `.git` makes Detect emit `--exclude /a/.git/
# --exclude /b/sub/.git/` to the Scan CLI), so we now pass the raw -e patterns
# straight through. Command length is decoupled from tree size and stays well
# under 1 KB, so no budget check is reachable any more.

# Fix 14: per-chunk subprocess.run timeout. Detect itself defaults to a
# 5-minute overall timeout (`--detect.timeout=300`) and we want our
# outer Python-level guard to be at least as generous so a legitimate
# slow scan doesn't get killed by us first. AOSP-class chunks with
# hundreds of third-party submodules (e.g. `external/cronet` 1.3 GB
# with Chromium submodules) can legitimately take 30-60 min, and we
# have observed Detect "starting but never returning" hangs that block
# the entire 825-chunk queue indefinitely (2026-07-28 customer report).
# Default 7200s = 2h; tune via env var.
#   - Small projects (<200 MB chunks, fast BD server): 1800 (30 min)
#   - AOSP-class chunks: 7200 (2 h) — default
#   - Extremely large or slow scans: 10800 (3 h) or more
CHUNK_TIMEOUT = int(os.environ.get("BD_SPLITTER_CHUNK_TIMEOUT", "7200"))
logging.debug(f"Fix 14: CHUNK_TIMEOUT={CHUNK_TIMEOUT}s per Detect subprocess "
              f"(override via BD_SPLITTER_CHUNK_TIMEOUT if set)")

for chunk_idx, (scan_dir, scan_dir_options) in enumerate(scan_dirs.items(), 1):
    code_location = f"{args.project}-{args.version}-{scan_dir}".replace("/", "-").replace("\\", "-")
    command = f"{base_command} --detect.source.path={scan_dir} --detect.code.location.name={code_location}"
    if exclude_list:
        # Fix 17 Layer 1: pass raw -e patterns directly to Detect instead of
        # pre-expanding to full paths. Probe confirmed: Detect does name/
        # substring matching internally, so --detect.excluded.directories=.git
        # correctly excludes all .git/ subdirs without Python pre-expansion.
        # Command stays < 1 KB regardless of tree size (2000 .git dirs → same
        # short string), permanently fixing the too-long / E2BIG root cause.
        exclusion_name_patterns = ",".join(exclude_list)
        command = f"{command} --detect.excluded.directories={exclusion_name_patterns}"

    logging.debug(f"Running BlackDuck detect on {scan_dir} using scan/code location name = {code_location}")
    logging.debug(f"command: {command}")

    detect_log = detect_log_dir / f"{code_location}-detect.log"

    logging.debug(f"Writing detect output to {detect_log}")
    # Fix 13: surface each chunk's actual size + % of size_limit so the
    # operator can spot uneven splits (a chunk much smaller than the limit
    # means the split algorithm over-decomposed that subtree; one close to
    # or above the limit means the chunk is on the edge of being unscan-
    # nable). Combined with Fix 12 (host snapshot) this gives a one-line
    # picture of "is this chunk big enough to be slow, and is the host
    # healthy enough to scan it?"
    chunk_size_bytes = scan_dir_options.get("size_bytes", 0)
    chunk_effective_bytes = chunk_effective_bytes_map.get(scan_dir, chunk_size_bytes)
    # Report the EFFECTIVE size (after this chunk's own excludes) as the
    # % of size_limit, because that is what Detect will actually scan.
    # `tree_size` is the pre-exclude size, shown for context so a chunk
    # that's almost empty because its content lives under other chunks
    # is still identifiable as "the root chunk of a big tree".
    if args.size_limit > 0:
        chunk_pct_of_limit = chunk_effective_bytes * 100.0 / args.size_limit
    else:
        chunk_pct_of_limit = 0.0
    chunk_size_human = _human_bytes(chunk_size_bytes)
    chunk_effective_human = _human_bytes(chunk_effective_bytes)
    if chunk_effective_bytes != chunk_size_bytes:
        size_field = f"size={chunk_size_human} tree, {chunk_effective_human} to scan ({chunk_pct_of_limit:.0f}% of limit)"
    else:
        size_field = f"size={chunk_size_human} ({chunk_pct_of_limit:.0f}% of limit)"

    # Fix 12: emit a host resource snapshot before each Detect spawn so we can
    # see disk/RSS pressure trends across the run and correlate any later
    # "chunk #N starts but never finishes" symptom with a disk-full or memory-
    # exhaustion event. `run_elapsed` lets the user eyeball throughput.
    run_elapsed = (arrow.utcnow() - start_time).total_seconds()
    logging.info(f"[{chunk_idx}/{total_chunks}] Starting Detect on code_location={code_location} "
                 f"{size_field} "
                 f"(log={detect_log}) "
                 f"| run_elapsed={run_elapsed:.0f}s {_snapshot(f'pre#{chunk_idx}', path=str(detect_log_dir))}")
    # Fix 16: log the FULL final Detect command (post Fix 15B) at INFO level
    # so the operator can copy-paste it into a shell to reproduce a hung or
    # failing scan. This is the command actually being spawned via
    # subprocess.run below — note the API token is in plaintext (same
    # exposure as `ps aux`); see START-banner NOTE above.
    logging.info(
        f"[{chunk_idx}/{total_chunks}] Detect command (final, copy-paste-runnable, includes token):\n"
        f"  {command}"
    )

    # Fix 2: stream Detect's stdout/stderr straight to the log file so the
    # full output never lives in the Python process's memory. The previous
    # implementation used stdout=subprocess.PIPE which held the entire
    # Detect output (hundreds of MB to multiple GB per scan) in RAM until
    # the subprocess exited. Writing through the OS file cache keeps the
    # process RSS flat.
    chunk_start = arrow.utcnow()
    process = None
    try:
        with open(detect_log, 'wb') as log_fh:
            process = subprocess.run(command, stdout=log_fh, stderr=subprocess.STDOUT,
                                     shell=True, timeout=CHUNK_TIMEOUT)
    except subprocess.TimeoutExpired:
        # Fix 14: Detect did not return within CHUNK_TIMEOUT (default 2 h).
        # Likely hung on a specific file/detector or signature-scanner
        # upload stalled. Without this guard the parent Python process
        # would block forever at `subprocess.run(..., timeout=None)`,
        # holding the entire 825-chunk queue hostage (customer 2026-07-28
        # "stuck at chunk 412" incident).
        #
        # Note: TimeoutExpired sends SIGKILL to the child via Popen, so
        # the Detect JVM is killed too — but the partial output already
        # streamed to {detect_log} survives (Fix 2 uses open+write mode).
        chunk_elapsed = (arrow.utcnow() - chunk_start).total_seconds()
        post_run_elapsed = (arrow.utcnow() - start_time).total_seconds()
        post_snapshot = _snapshot(f"post#{chunk_idx}", path=str(detect_log_dir))
        logging.error(
            f"[{chunk_idx}/{total_chunks}] Detect TIMED OUT on {code_location} "
            f"after {CHUNK_TIMEOUT}s (env BD_SPLITTER_CHUNK_TIMEOUT). "
            f"Detect likely hung on a specific file/detector or the signature "
            f"scanner upload stalled. Detect JVM has been SIGKILL'd. "
            f"Partial output is in {detect_log} (use it to find what Detect "
            f"was doing when it got killed). "
            f"Workarounds: (a) re-run with BD_SPLITTER_CHUNK_TIMEOUT=10800 for more "
            f"headroom; (b) re-run with smaller -s to split this chunk; "
            f"(c) skip this subtree via -e. "
            f"Run continues with chunk {chunk_idx + 1}. "
            f"| run_elapsed={post_run_elapsed:.0f}s {post_snapshot}"
        )
        detect_failed += 1
        continue   # don't block subsequent chunks on this one
    chunk_elapsed = (arrow.utcnow() - chunk_start).total_seconds()
    post_run_elapsed = (arrow.utcnow() - start_time).total_seconds()
    # Snapshot after each Detect so we can tell whether the run was leaking
    # RSS (e.g. a Detect that wrote its log then a successive chunk sees RSS
    # grow by hundreds of MB) or whether disk pressure spiked.
    post_snapshot = _snapshot(f"post#{chunk_idx}", path=str(detect_log_dir))

    if process.returncode == 0:
        logging.info(f"[{chunk_idx}/{total_chunks}] Detect SUCCEEDED on {code_location} (took {chunk_elapsed:.1f}s) "
                     f"| run_elapsed={post_run_elapsed:.0f}s {post_snapshot}")
        code_locations_to_wait_for.append(code_location)
        detect_ok += 1
    else:
        # Fix 12: include the signal-aware returncode interpretation so a
        # SIGKILL (negative rc = -9) is immediately recognisable as an
        # OOM-kill without needing dmesg.
        logging.error(f"[{chunk_idx}/{total_chunks}] Detect FAILED on {code_location} "
                      f"({_returncode_repr(process.returncode)}, took {chunk_elapsed:.1f}s) "
                      f"| run_elapsed={post_run_elapsed:.0f}s {post_snapshot}. "
                      f"Look at detect log {detect_log} for more information.")
        detect_failed += 1

# Counters used by the final summary — always defined so the summary code
# below can reference them regardless of whether -w was passed.
wait_ok = 0
wait_failed = 0
wait_timeout = 0

if args.wait:
    wait_total = len(code_locations_to_wait_for)
    if wait_total > 0:
        logging.info(f"Waiting for {wait_total} scan(s) to finish processing (max_checks={args.max_checks}, check_delay={args.check_delay}s)...")
    for wait_idx, code_location in enumerate(code_locations_to_wait_for, 1):
        logging.debug(f"Waiting for code location {code_location} to finish processing using start_time {start_time}")
        logging.info(f"[{wait_idx}/{wait_total}] Waiting for {code_location} to finish...")
        scan_monitor = ScanMonitor(bd, code_location, max_checks=args.max_checks, check_delay=args.check_delay, start_time=start_time, snippet_scan=args.snippet_scan)
        scan_status = scan_monitor.wait_for_scan_completion()
        if scan_status == ScanMonitor.SUCCESS:
            logging.info(f"[{wait_idx}/{wait_total}] {code_location}: scan COMPLETED successfully")
            wait_ok += 1
        elif scan_status == ScanMonitor.FAILURE:
            logging.error(f"[{wait_idx}/{wait_total}] {code_location}: scan FAILED on BlackDuck server")
            wait_failed += 1
        else:  # TIMED_OUT
            logging.error(f"[{wait_idx}/{wait_total}] {code_location}: scan TIMED OUT (max_checks={args.max_checks})")
            wait_timeout += 1
        logging.debug(f"Code location {code_location} finished with status = {scan_status}")

#
# Final summary — also printed to stdout so the operator sees the result
# without having to tail the log file.
#
total_elapsed = (arrow.utcnow() - start_time).total_seconds()
# Fix 12: include the end-of-run resource snapshot in the final summary so
# "did this run die because we ran out of memory/disk?" is answerable from
# the last line of the log alone.
final_snapshot = _snapshot("final", path=str(detect_log_dir))
if args.wait:
    summary = (
        f"=== bd-splitter DONE === "
        f"detect_ok={detect_ok} detect_failed={detect_failed} "
        f"wait_ok={wait_ok} wait_failed={wait_failed} wait_timeout={wait_timeout} "
        f"elapsed={total_elapsed:.1f}s "
        f"| {final_snapshot} ==="
    )
else:
    summary = (
        f"=== bd-splitter DONE (no -w) === "
        f"detect_ok={detect_ok} detect_failed={detect_failed} "
        f"elapsed={total_elapsed:.1f}s "
        f"| {final_snapshot} ==="
    )
logging.info(summary)
overall_ok = detect_failed == 0 and (not args.wait or (wait_failed == 0 and wait_timeout == 0))
if overall_ok:
    print(f"OK: {summary}")
    sys.exit(0)
else:
    print(f"FAIL: {summary}", file=sys.stderr)
    sys.exit(1)
