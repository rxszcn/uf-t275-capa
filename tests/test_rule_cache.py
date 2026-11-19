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
import textwrap
import contextlib
from pathlib import Path

import capa.rules
import capa.helpers
import capa.rules.cache

R1 = capa.rules.Rule.from_yaml(
    textwrap.dedent("""
    rule:
        meta:
            name: test rule
            authors:
                - user@domain.com
            scopes:
                static: function
                dynamic: process
            examples:
                - foo1234
                - bar5678
        features:
            - and:
                - number: 1
                - number: 2
    """)
)

R2 = capa.rules.Rule.from_yaml(
    textwrap.dedent("""
    rule:
        meta:
            name: test rule 2
            authors:
                - user@domain.com
            scopes:
                static: function
                dynamic: process
            examples:
                - foo1234
                - bar5678
        features:
            - and:
                - number: 3
                - number: 4
    """)
)


def test_ruleset_cache_ids():
    rs = capa.rules.RuleSet([R1])
    content = capa.rules.cache.get_ruleset_content(rs)

    rs2 = capa.rules.RuleSet([R1, R2])
    content2 = capa.rules.cache.get_ruleset_content(rs2)

    id = capa.rules.cache.compute_cache_identifier(content)
    id2 = capa.rules.cache.compute_cache_identifier(content2)
    assert id != id2


def test_ruleset_cache_save_load():
    rs = capa.rules.RuleSet([R1])
    content = capa.rules.cache.get_ruleset_content(rs)

    id = capa.rules.cache.compute_cache_identifier(content)
    assert id is not None

    cache_dir = capa.rules.cache.get_default_cache_directory()

    path = capa.rules.cache.get_cache_path(cache_dir, id)
    with contextlib.suppress(OSError):
        path.unlink()

    capa.rules.cache.cache_ruleset(cache_dir, rs)
    assert path.exists()

    assert capa.rules.cache.load_cached_ruleset(cache_dir, content) is not None


def test_ruleset_cache_invalid():
    rs = capa.rules.RuleSet([R1])
    content = capa.rules.cache.get_ruleset_content(rs)
    id = capa.rules.cache.compute_cache_identifier(content)
    cache_dir = capa.rules.cache.get_default_cache_directory()
    path = capa.rules.cache.get_cache_path(cache_dir, id)
    with contextlib.suppress(OSError):
        path.unlink()

    capa.rules.cache.cache_ruleset(cache_dir, rs)
    assert path.exists()

    buf = path.read_bytes()

    # corrupt the magic header
    buf = b"x" + buf[1:]

    # write the modified contents back to the file
    path.write_bytes(buf)

    # check if the file still exists
    assert path.exists()
    assert capa.rules.cache.load_cached_ruleset(cache_dir, content) is None
    # the invalid cache should be deleted
    assert not path.exists()


def test_rule_cache_dev_environment():
    # generate rules cache
    rs = capa.rules.RuleSet([R2])
    content = capa.rules.cache.get_ruleset_content(rs)
    id = capa.rules.cache.compute_cache_identifier(content)
    cache_dir = capa.rules.cache.get_default_cache_directory()
    cache_path = capa.rules.cache.get_cache_path(cache_dir, id)

    # clear existing cache files
    for f in cache_dir.glob("*.cache"):
        f.unlink()

    capa.rules.cache.cache_ruleset(cache_dir, rs)
    assert cache_path.exists()

    assert capa.helpers.is_cache_newer_than_rule_code(cache_dir) is True

    capa_root = Path(__file__).resolve().parent.parent
    cachepy = capa_root / "capa" / "rules" / "cache.py"  # alternative: capa_root / "capa" / "rules" / "__init__.py"

    # set cache's last modified time prior to code file's modified time
    os.utime(cache_path, (cache_path.stat().st_atime, cachepy.stat().st_mtime - 600000))

    # debug
    def ts_to_str(ts):
        from datetime import datetime

        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    for g in ((capa_root / "capa" / "rules").glob("*.py"), cache_dir.glob("*.cache")):
        for p in g:
            print(p, "\t", ts_to_str(p.stat().st_mtime))  # noqa: T201

    assert capa.helpers.is_dev_environment() is True
    assert capa.helpers.is_cache_newer_than_rule_code(cache_dir) is False


# rule content used by the graduation (pure move) scenarios below.
# note: the test function names must not contain "nursery",
# because pytest's tmp_path embeds the test name and
# capa.rules.is_nursery_rule_path() inspects the path parts.
MOVED_RULE_YAML = textwrap.dedent("""
    rule:
        meta:
            name: graduated test rule
            authors:
                - user@domain.com
            scopes:
                static: function
                dynamic: process
            examples:
                - foo1234
        features:
            - and:
                - number: 1
                - number: 2
    """)


def _make_graduated_rule_layout(tmp_path):
    """
    create a rules directory holding a single rule file in the nursery subdirectory,
    build the ruleset cache from that layout, then graduate the rule by moving the
    file, unchanged, into the main rules directory.

    returns (rules_dir, cache_dir, graduated_path, cache_path, cache_bytes).
    """
    rules_dir = tmp_path / "rules"
    nursery_dir = rules_dir / "nursery"
    nursery_dir.mkdir(parents=True)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    rule_file = nursery_dir / "graduated-test-rule.yml"
    rule_file.write_text(MOVED_RULE_YAML, encoding="utf-8")

    ruleset = capa.rules.get_rules([rules_dir], cache_dir=cache_dir, enable_cache=True)
    (rule,) = ruleset.rules.values()
    assert rule.meta["capa/path"] == rule_file.as_posix()
    assert rule.meta["capa/nursery"] is True

    # the cache file now exists and must remain untouched by the scenarios below.
    cache_paths = list(cache_dir.glob("*.cache"))
    assert len(cache_paths) == 1
    cache_bytes = cache_paths[0].read_bytes()

    # graduate the rule: a pure move, the file content does not change.
    graduated_path = rules_dir / "graduated-test-rule.yml"
    rule_file.rename(graduated_path)
    assert not rule_file.exists()

    return rules_dir, cache_dir, graduated_path, cache_paths[0], cache_bytes


def test_ruleset_cache_hit_after_rule_move(tmp_path):
    rules_dir, cache_dir, graduated_path, cache_path, cache_bytes = _make_graduated_rule_layout(tmp_path)

    # reload with the cache enabled: the rule content is unchanged, so this must be a cache hit.
    parsed = []
    ruleset_cached = capa.rules.get_rules(
        [rules_dir],
        cache_dir=cache_dir,
        on_load_rule=lambda path, i, total: parsed.append(path),
        enable_cache=True,
    )

    # a cache hit must not fall back to re-parsing rule files.
    assert parsed == []
    # the cache file must still exist and must not have been rewritten.
    assert cache_path.exists()
    assert cache_path.read_bytes() == cache_bytes

    # control group: reload with the cache explicitly disabled.
    ruleset_uncached = capa.rules.get_rules([rules_dir], cache_dir=cache_dir, enable_cache=False)

    # both groups must report the rule's current on-disk path and graduated (non-nursery) flag.
    for ruleset in (ruleset_cached, ruleset_uncached):
        (rule,) = ruleset.rules.values()
        assert rule.meta["capa/path"] == graduated_path.as_posix()
        assert rule.meta["capa/nursery"] is False


def test_ruleset_no_cache_after_rule_move(tmp_path):
    rules_dir, cache_dir, graduated_path, _, _ = _make_graduated_rule_layout(tmp_path)

    # control group: with the cache disabled, metadata comes straight from the file system.
    ruleset = capa.rules.get_rules([rules_dir], cache_dir=cache_dir, enable_cache=False)
    (rule,) = ruleset.rules.values()
    assert rule.meta["capa/path"] == graduated_path.as_posix()
    assert rule.meta["capa/nursery"] is False
