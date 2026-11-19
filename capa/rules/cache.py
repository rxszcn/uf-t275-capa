# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import zlib
import pickle
import hashlib
import logging
from typing import Optional
from pathlib import Path
from dataclasses import dataclass

import capa.rules
import capa.version

logger = logging.getLogger(__name__)


# TypeAlias. note: using `foo: TypeAlias = bar` is Python 3.10+
CacheIdentifier = str


def compute_cache_identifier(rule_content: list[bytes]) -> CacheIdentifier:
    hash = hashlib.sha256()

    # note that this changes with each release,
    # so cache identifiers will never collide across releases.
    version = capa.version.__version__

    hash.update(version.encode("utf-8"))
    hash.update(b"\x00")

    rule_hashes = sorted([hashlib.sha256(buf).hexdigest() for buf in rule_content])
    for rule_hash in rule_hashes:
        hash.update(rule_hash.encode("ascii"))
        hash.update(b"\x00")

    return hash.hexdigest()


def get_default_cache_directory() -> Path:
    # ref: https://github.com/mandiant/capa/issues/1212#issuecomment-1361259813
    #
    # Linux:   $XDG_CACHE_HOME/capa/
    # Windows: %LOCALAPPDATA%\flare\capa\cache
    # MacOS:   ~/Library/Caches/capa

    # ref: https://stackoverflow.com/a/8220141/87207
    if sys.platform.startswith(("linux", "freebsd", "openbsd", "netbsd", "dragonfly")):
        directory = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache" / "capa"))
    elif sys.platform == "darwin":
        directory = Path.home() / "Library" / "Caches" / "capa"
    elif sys.platform == "win32":
        directory = Path(os.environ["LOCALAPPDATA"]) / "flare" / "capa" / "cache"
    else:
        raise NotImplementedError(f"unsupported platform: {sys.platform}")

    directory.mkdir(parents=True, exist_ok=True)

    return directory


def get_cache_path(cache_dir: Path, id: CacheIdentifier) -> Path:
    filename = "capa-" + id[:8] + ".cache"
    return cache_dir / filename


MAGIC = b"capa"
VERSION = b"\x00\x00\x00\x01"


@dataclass
class RuleCache:
    id: CacheIdentifier
    ruleset: capa.rules.RuleSet

    def dump(self):
        return MAGIC + VERSION + self.id.encode("ascii") + zlib.compress(pickle.dumps(self))

    @staticmethod
    def load(data):
        assert data.startswith(MAGIC + VERSION)

        id = data[0x8:0x48].decode("ascii")
        cache = pickle.loads(zlib.decompress(data[0x48:]))

        assert isinstance(cache, RuleCache)
        assert cache.id == id

        return cache


def get_ruleset_content(ruleset: capa.rules.RuleSet) -> list[bytes]:
    rule_contents = []
    for rule in ruleset.rules.values():
        if rule.is_subscope_rule():
            continue
        rule_contents.append(rule.definition.encode("utf-8"))
    return rule_contents


def compute_ruleset_cache_identifier(ruleset: capa.rules.RuleSet) -> CacheIdentifier:
    rule_contents = get_ruleset_content(ruleset)
    return compute_cache_identifier(rule_contents)


def cache_ruleset(cache_dir: Path, ruleset: capa.rules.RuleSet):
    """
    cache the given ruleset to disk, using the given cache directory.
    this can subsequently be reloaded via `load_cached_ruleset`,
    assuming the capa version and rule content does not change.

    callers should use this function to avoid the performance overhead
    of validating rules on each run.
    """
    id = compute_ruleset_cache_identifier(ruleset)
    path = get_cache_path(cache_dir, id)
    if path.exists():
        logger.debug("rule set already cached to %s", path)
        return

    cache = RuleCache(id, ruleset)
    path.write_bytes(cache.dump())

    logger.debug("rule set cached to %s", path)
    return


def refresh_ruleset_path_metadata(
    ruleset: capa.rules.RuleSet, rule_file_paths: list[Path], rule_contents: list[bytes]
) -> None:
    """
    refresh the path-derived metadata (`capa/path` and `capa/nursery`) of the rules
    in the given ruleset so that it reflects the current on-disk rule file layout.

    the cache identifier is derived from rule *content* only (see `compute_cache_identifier`),
    so a cached ruleset may outlive pure moves of rule files, such as a rule graduating
    from the nursery subdirectory into the main rules directory without any content change.
    without this refresh, a cache hit would keep reporting the rule's old path
    and a stale nursery flag.

    rules are matched to files by content hash. when multiple files share identical
    content (ambiguous), a rule keeps its current path if it is still among the
    candidates, and otherwise the lexicographically smallest candidate path is chosen,
    so the result is deterministic.

    note: this mutates the rules of the given ruleset in place.
    """
    paths_by_hash: dict[str, list[Path]] = {}
    for path, content in zip(rule_file_paths, rule_contents):
        paths_by_hash.setdefault(hashlib.sha256(content).hexdigest(), []).append(path)

    for rule in ruleset.rules.values():
        if rule.is_subscope_rule():
            # subscope rules are derived from their parent rule and don't map to a file on disk.
            continue

        rule_hash = hashlib.sha256(rule.definition.encode("utf-8")).hexdigest()
        candidates = paths_by_hash.get(rule_hash)
        if not candidates:
            # the cache identifier covers all rule contents, so a matching cache implies
            # every rule's content is still on disk; be defensive anyway and keep
            # the existing metadata rather than dropping the rule.
            logger.warning("no rule file found on disk for cached rule: %s", rule.name)
            continue

        current_path = rule.meta.get("capa/path")
        candidate_paths = [path.as_posix() for path in candidates]
        if current_path in candidate_paths:
            new_path = Path(str(current_path))
        else:
            new_path = min(candidates, key=lambda p: p.as_posix())

        rule.meta["capa/path"] = new_path.as_posix()
        rule.meta["capa/nursery"] = capa.rules.is_nursery_rule_path(new_path)


def load_cached_ruleset(cache_dir: Path, rule_contents: list[bytes]) -> Optional[capa.rules.RuleSet]:
    """
    load a cached ruleset from disk, using the given cache directory.
    the raw rule contents are required here to prove that the rules haven't changed
    and to avoid stale cache entries.

    callers should use this function to avoid the performance overhead
    of validating rules on each run.
    """
    id = compute_cache_identifier(rule_contents)
    path = get_cache_path(cache_dir, id)
    if not path.exists():
        logger.debug("rule set cache does not exist: %s", path)
        return None

    logger.debug("loading rule set from cache: %s", path)
    buf = path.read_bytes()

    try:
        cache = RuleCache.load(buf)
    except AssertionError:
        logger.debug("rule set cache is invalid: %s", path)
        # delete the cache that seems to be invalid.
        path.unlink()
        return None

    return cache.ruleset


def generate_rule_cache(rules_dir: Path, cache_dir: Path) -> bool:
    if not rules_dir.is_dir():
        logger.error("rules directory %s does not exist", rules_dir)
        return False

    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        rules = capa.rules.get_rules([rules_dir], cache_dir)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return False

    content = get_ruleset_content(rules)
    id = compute_cache_identifier(content)
    path = get_cache_path(cache_dir, id)

    assert path.exists()
    logger.info("rules cache saved to: %s", path)

    return True
