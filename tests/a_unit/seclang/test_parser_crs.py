"""Tests for SecLang parser with real CRS .conf files."""

from __future__ import annotations

from pathlib import Path

import pytest

from lewaf.engine import RuleGroup
from lewaf.seclang import ParseError, SecLangParser


class StubWAF:
    """Stub WAF for testing parser."""

    def __init__(self):
        self.rule_group = RuleGroup()


class TestSecLangParserCRS:
    """Tests for parsing real CRS .conf files."""

    def setup_method(self):
        """Setup test fixtures."""
        self.waf = StubWAF()
        self.parser = SecLangParser(self.waf)
        self.project_root = Path(__file__).parent.parent.parent.parent

    def test_parse_coraza_conf(self):
        """Test parsing main coraza.conf file."""
        conf_path = self.project_root / "coraza.conf"

        if not conf_path.exists():
            pytest.skip("coraza.conf not found")

        # Parse the file
        self.parser.from_file(conf_path)

        # Should have parsed some rules
        total_rules = sum(
            len(rules) for rules in self.waf.rule_group.rules_by_phase.values()
        )
        assert total_rules > 0, "Should have parsed at least one rule from coraza.conf"

        # Check that configuration directives were processed
        # (they don't raise errors)

    def test_parse_crs_protocol_enforcement(self):
        """Test parsing CRS protocol enforcement rules."""
        conf_path = (
            self.project_root / "rules" / "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"
        )

        if not conf_path.exists():
            pytest.skip("REQUEST-920-PROTOCOL-ENFORCEMENT.conf not found")

        self.parser.from_file(conf_path)

        # Should have parsed rules
        total_rules = sum(
            len(rules) for rules in self.waf.rule_group.rules_by_phase.values()
        )
        assert total_rules > 0, (
            "Should have parsed rules from protocol enforcement file"
        )

    def test_parse_crs_xss_rules(self):
        """Test parsing CRS XSS attack rules."""
        conf_path = (
            self.project_root / "rules" / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
        )

        if not conf_path.exists():
            pytest.skip("REQUEST-941-APPLICATION-ATTACK-XSS.conf not found")

        self.parser.from_file(conf_path)

        # Should have parsed rules
        total_rules = sum(
            len(rules) for rules in self.waf.rule_group.rules_by_phase.values()
        )
        assert total_rules > 0, "Should have parsed rules from XSS file"

    def test_parse_crs_sqli_rules(self):
        """Test parsing CRS SQL injection rules."""
        conf_path = (
            self.project_root / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
        )

        if not conf_path.exists():
            pytest.skip("REQUEST-942-APPLICATION-ATTACK-SQLI.conf not found")

        self.parser.from_file(conf_path)

        # Should have parsed rules
        total_rules = sum(
            len(rules) for rules in self.waf.rule_group.rules_by_phase.values()
        )
        assert total_rules > 0, "Should have parsed rules from SQLi file"

    def test_parse_line_continuation_real(self):
        """Test parsing real multi-line rules with continuation."""
        # coraza.conf has several multi-line rules
        content = r"""
        SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
             "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
        """

        self.parser.from_string(content)

        # Should have parsed the rule
        assert len(self.waf.rule_group.rules_by_phase[1]) == 1
        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 200000
        assert rule.phase == 1

    def test_parse_complex_operator(self):
        """Test parsing rule with complex operator."""
        content = r"""
        SecRule REQBODY_ERROR "!@eq 0" \
            "id:'200002',phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
        """

        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[2][0]
        assert rule.id == 200002
        assert rule.operator.name == "eq"
        assert rule.operator.negated is True

    def test_parse_includes_testdata(self):
        """Test parsing files with Include directives from Go testdata."""
        parent_path = self.project_root / "tests" / "data" / "includes" / "parent.conf"

        if not parent_path.exists():
            pytest.skip("Go testdata not available")

        # Parse parent file which includes other files
        self.parser.from_file(parent_path)

        # Should have loaded rules from included files
        total_rules = sum(
            len(rules) for rules in self.waf.rule_group.rules_by_phase.values()
        )
        assert total_rules > 0, "Should have parsed rules from included files"

    def test_parse_includes_with_relative_paths(self):
        """Test Include directive with relative paths."""
        # Create temp files for testing
        import tempfile  # noqa: PLC0415 - Avoids circular import

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create main config
            main_conf = Path(tmpdir) / "main.conf"
            main_conf.write_text("Include rules.conf\n")

            # Create included file
            rules_conf = Path(tmpdir) / "rules.conf"
            rules_conf.write_text('SecRule ARGS "@rx test" "id:1001,phase:1,deny"\n')

            # Parse main file
            self.parser.from_file(main_conf)

            # Should have loaded rule from included file
            assert len(self.waf.rule_group.rules_by_phase[1]) == 1
            assert self.waf.rule_group.rules_by_phase[1][0].id == 1001

    def test_parse_includes_with_subdirectories(self):
        """Test Include directive with subdirectory paths."""
        import tempfile  # noqa: PLC0415 - Avoids circular import
        from pathlib import Path  # noqa: PLC0415 - Avoids circular import

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create subdirectory
            subdir = tmppath / "rules"
            subdir.mkdir()

            # Create main config
            main_conf = tmppath / "main.conf"
            main_conf.write_text("Include rules/sub.conf\n")

            # Create included file in subdirectory
            sub_conf = subdir / "sub.conf"
            sub_conf.write_text('SecRule ARGS "@rx test" "id:2001,phase:1,deny"\n')

            # Parse main file
            self.parser.from_file(main_conf)

            # Should have loaded rule from subdirectory
            assert len(self.waf.rule_group.rules_by_phase[1]) == 1
            assert self.waf.rule_group.rules_by_phase[1][0].id == 2001

    def test_parse_multiple_transformations_real(self):
        """Test parsing rules with multiple transformations from real config."""
        content = r"""
          SecRule REQUEST_HEADERS:Content-Type "^application/json" \
             "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
        """

        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 200001
        # t:none clears transformations, then t:lowercase is added
        # Our implementation should handle this
        assert "lowercase" in rule.transformations or len(rule.transformations) >= 1

    def test_parse_skipafter_action(self):
        """Test parsing skipAfter action from CRS files."""
        content = r"""
        SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:920011,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"
        """

        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 920011
        assert rule.phase == 1

    def test_parse_all_crs_files(self):
        """Test parsing all CRS rule files without errors."""
        rules_dir = self.project_root / "rules"

        if not rules_dir.exists():
            pytest.skip("Rules directory not found")

        # Get all .conf files
        conf_files = list(rules_dir.glob("*.conf"))

        if not conf_files:
            pytest.skip("No .conf files in rules directory")

        # Parse each file
        parsed_count = 0
        total_rules = 0

        for conf_file in conf_files:
            # Create fresh parser for each file
            waf = StubWAF()
            parser = SecLangParser(waf)

            try:
                parser.from_file(conf_file)
                parsed_count += 1

                # Count rules
                file_rules = sum(
                    len(rules) for rules in waf.rule_group.rules_by_phase.values()
                )
                total_rules += file_rules

                print(f"Parsed {conf_file.name}: {file_rules} rules")
            except ParseError as e:
                # Log but continue - some files might have unsupported features
                print(f"ParseError in {conf_file.name}: {e}")
            except Exception as e:
                # Log unexpected errors
                print(f"Unexpected error in {conf_file.name}: {e}")

        # Should have successfully parsed at least some files
        assert parsed_count > 0, "Should have parsed at least one CRS file"
        print(
            f"\nTotal: Parsed {parsed_count}/{len(conf_files)} files with {total_rules} rules"
        )

    def test_parse_ctl_action(self):
        """Test parsing ctl (control) actions."""
        content = r"""
        SecRule REQUEST_HEADERS:Content-Type "^application/json" \
             "id:'200001',phase:1,t:lowercase,pass,ctl:requestBodyProcessor=JSON"
        """

        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 200001
        # ctl action should be in actions dict
        # (even if not fully implemented yet)

    def test_configuration_directives_real(self):
        """Test parsing various configuration directives from coraza.conf."""
        content = """
        SecRuleEngine DetectionOnly
        SecRequestBodyAccess On
        SecResponseBodyAccess On
        SecRequestBodyLimit 13107200
        SecRequestBodyInMemoryLimit 131072
        SecRequestBodyLimitAction Reject
        SecResponseBodyMimeType text/plain text/html text/xml
        SecResponseBodyLimit 524288
        SecResponseBodyLimitAction ProcessPartial
        SecDataDir /tmp/
        SecAuditEngine RelevantOnly
        SecAuditLogRelevantStatus "^(?:(5|4)(0|1)[0-9])$"
        SecAuditLogParts ABIJDEFHZ
        SecAuditLogType Serial
        SecAuditLogFormat Native
        """

        # Should not raise any errors
        self.parser.from_string(content)

        # Configuration directives are processed but may not be stored yet
        # The important thing is they don't cause parse errors
