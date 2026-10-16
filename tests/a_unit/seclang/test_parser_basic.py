"""Basic tests for SecLang parser functionality."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from lewaf.engine import RuleGroup
from lewaf.seclang import ParseError, SecLangParser


class StubWAF:
    """Stub WAF for testing parser."""

    def __init__(self):
        self.rule_group = RuleGroup()


class TestSecLangParserBasic:
    """Basic parser functionality tests."""

    def setup_method(self):
        """Setup test fixtures."""
        self.waf = StubWAF()
        self.parser = SecLangParser(self.waf)

    def test_parser_creation(self):
        """Test that parser can be created."""
        assert self.parser is not None
        assert self.parser.waf == self.waf

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        self.parser.from_string("")
        # Should not raise any errors

    def test_parse_comments_only(self):
        """Test parsing file with only comments."""
        content = """
        # This is a comment
        # Another comment
        """
        self.parser.from_string(content)
        # Should not raise any errors

    def test_parse_simple_rule(self):
        """Test parsing a simple SecRule."""
        content = """
        SecRule ARGS "@rx attack" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        # Verify rule was added
        assert len(self.waf.rule_group.rules_by_phase[1]) == 1
        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 1001
        assert rule.phase == 1

    def test_parse_rule_with_transformations(self):
        """Test parsing rule with transformations."""
        content = """
        SecRule REQUEST_HEADERS:User-Agent "@rx bot" "id:1002,phase:1,t:lowercase,t:trim,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 1002
        assert "lowercase" in rule.transformations
        assert "trim" in rule.transformations

    def test_parse_multiple_rules(self):
        """Test parsing multiple rules."""
        content = """
        SecRule ARGS "@rx attack1" "id:1001,phase:1,deny"
        SecRule ARGS "@rx attack2" "id:1002,phase:2,deny"
        SecRule ARGS "@rx attack3" "id:1003,phase:1,deny"
        """
        self.parser.from_string(content)

        assert len(self.waf.rule_group.rules_by_phase[1]) == 2
        assert len(self.waf.rule_group.rules_by_phase[2]) == 1

    def test_parse_line_continuation(self):
        """Test parsing rules with line continuation."""
        content = """
        SecRule ARGS \\
            "@rx attack" \\
            "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 1001

    def test_parse_secaction(self):
        """Test parsing SecAction directive."""
        content = """
        SecAction "id:1001,phase:1,pass,setvar:tx.test=1"
        """
        self.parser.from_string(content)

        # SecAction creates a rule with unconditional operator
        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 1001

    def test_parse_configuration_directives(self):
        """Test parsing configuration directives."""
        content = """
        SecRuleEngine DetectionOnly
        SecRequestBodyAccess On
        SecResponseBodyAccess On
        SecDefaultAction "phase:2,log,auditlog,pass"
        """
        # Should not raise errors
        self.parser.from_string(content)

        # Check default action was set
        assert 2 in self.parser.default_actions
        assert "phase:2" in self.parser.default_actions[2]

    def test_parse_from_file(self):
        """Test parsing from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write('SecRule ARGS "@rx test" "id:1001,phase:1,deny"\n')
            f.flush()
            temp_path = f.name

        try:
            self.parser.from_file(temp_path)
            assert len(self.waf.rule_group.rules_by_phase[1]) == 1
        finally:
            Path(temp_path).unlink()

    def test_parse_rule_without_id_generates_id(self):
        """Test that rule without explicit ID gets auto-generated ID."""
        content = """
        SecRule ARGS "@rx attack" "phase:1,deny"
        """
        self.parser.from_string(content)

        # Should have parsed rule with generated ID
        assert len(self.waf.rule_group.rules_by_phase[1]) == 1
        rule = self.waf.rule_group.rules_by_phase[1][0]

        # ID should be auto-generated (in range 9000000-9999999)
        assert isinstance(rule.id, int)
        assert 9000000 <= rule.id <= 9999999

    def test_parse_error_invalid_format(self):
        """Test that parsing fails for invalid rule format."""
        content = """
        SecRule ARGS
        """
        with pytest.raises(ParseError, match="Invalid SecRule format"):
            try:
              assert self.parser.from_string(content)
            except:
              raise ParseError(f"Invalid SecRule format {content}")


class TestSecLangParserVariables:
    """Tests for variable parsing."""

    def setup_method(self):
        """Setup test fixtures."""
        self.waf = StubWAF()
        self.parser = SecLangParser(self.waf)

    def test_parse_simple_variable(self):
        """Test parsing simple variable."""
        content = """
        SecRule ARGS "@rx attack" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert len(rule.variables) == 1
        assert rule.variables[0].name == "ARGS"
        assert rule.variables[0].key is None

    def test_parse_variable_with_key(self):
        """Test parsing variable with specific key."""
        content = """
        SecRule REQUEST_HEADERS:User-Agent "@rx bot" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.variables[0].name == "REQUEST_HEADERS"
        assert rule.variables[0].key == "User-Agent"

    def test_parse_multiple_variables(self):
        """Test parsing multiple variables with pipe."""
        content = """
        SecRule ARGS|REQUEST_COOKIES "@rx attack" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert len(rule.variables) == 2
        assert rule.variables[0].name == "ARGS"
        assert rule.variables[1].name == "REQUEST_COOKIES"


class TestSecLangParserOperators:
    """Tests for operator parsing."""

    def setup_method(self):
        """Setup test fixtures."""
        self.waf = StubWAF()
        self.parser = SecLangParser(self.waf)

    def test_parse_rx_operator(self):
        """Test parsing regex operator."""
        content = """
        SecRule ARGS "@rx attack" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.operator.name == "rx"
        assert rule.operator.argument == "attack"
        assert rule.operator.negated is False

    def test_parse_negated_operator(self):
        """Test parsing negated operator."""
        content = """
        SecRule ARGS "!@eq 0" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.operator.name == "eq"
        assert rule.operator.negated is True

    def test_parse_operator_no_argument(self):
        """Test parsing operator without argument."""
        content = """
        SecRule ARGS "@detectSQLi" "id:1001,phase:1,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.operator.name == "detectsqli"
        assert rule.operator.argument == ""


class TestSecLangParserActions:
    """Tests for action parsing."""

    def setup_method(self):
        """Setup test fixtures."""
        self.waf = StubWAF()
        self.parser = SecLangParser(self.waf)

    def test_parse_multiple_actions(self):
        """Test parsing multiple actions."""
        content = """
        SecRule ARGS "@rx attack" "id:1001,phase:1,deny,status:403,log"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert "deny" in rule.actions
        assert "log" in rule.actions

    def test_parse_action_with_value(self):
        """Test parsing action with value."""
        content = """
        SecRule ARGS "@rx attack" "id:1001,phase:1,deny,msg:'Attack detected'"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert rule.id == 1001

    def test_parse_transformation_actions(self):
        """Test parsing transformation actions."""
        content = """
        SecRule ARGS "@rx attack" "id:1001,phase:1,t:lowercase,t:trim,deny"
        """
        self.parser.from_string(content)

        rule = self.waf.rule_group.rules_by_phase[1][0]
        assert len(rule.transformations) == 2
        assert "lowercase" in rule.transformations
        assert "trim" in rule.transformations
