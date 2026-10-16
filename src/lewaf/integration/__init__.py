from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any

from lewaf.engine import RuleGroup
from lewaf.primitives.actions import ACTIONS
from lewaf.primitives.operators import Operator, OperatorOptions, get_operator
from lewaf.rules import Rule, VariableSpec
from lewaf.transaction import Transaction
from lewaf.seclang.parser import SecLangParser as FileSecLangParser  # msc_pyparser-backed


@dataclass(frozen=True)
class ParsedOperator:
    """Container for parsed operator information."""

    name: str
    argument: str
    op: Operator
    negated: bool = False


@dataclass(frozen=True)
class SecLangParser:
    """Simple inline SecLang parser for individual rule strings.

    This parser handles single SecRule directives passed as strings (e.g., from
    configuration dicts). For parsing .conf files with Include directives,
    default actions, and markers, use `lewaf.seclang.SecLangParser` instead.

    Note: This class shares the same name as `lewaf.seclang.SecLangParser` but
    serves a different purpose. This one is for inline rules in WAF config:
        WAF({"rules": ['SecRule ARGS "@rx attack" "id:1,phase:1,deny"']})

    The file parser in lewaf.seclang handles:
        - Include/IncludeOptional directives
        - SecDefaultAction
        - SecMarker
        - Multi-file loading with glob patterns
    """

    rule_group: RuleGroup

    def _normalize_line_continuations(self, rule_str: str) -> str:
        """Normalize line continuations by removing backslash-newline sequences."""
        # Remove backslash followed by optional whitespace and newline
        # This handles cases like "action,\" followed by newline and indentation
        # Be more careful to only remove actual line continuations, not escaped quotes
        normalized = re.sub(r"\\\s*\n\s*", "", rule_str)
        return normalized

    def _split_actions(self, actions_str: str) -> list[str]:
        """Split actions string on commas, but respect quoted values."""
        actions = []
        current_action = ""
        in_quotes = False
        quote_char = None

        for char in actions_str:
            if char in {"'", '"'} and not in_quotes:
                in_quotes = True
                quote_char = char
                current_action += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                current_action += char
            elif char == "," and not in_quotes:
                if current_action.strip():
                    actions.append(current_action.strip())
                current_action = ""
            else:
                current_action += char

        # Add the last action if any
        if current_action.strip():
            actions.append(current_action.strip())

        return actions

    def from_string(self, rule_str: str):
        # Preprocess line continuations: remove backslash-newline sequences
        normalized_rule = self._normalize_line_continuations(rule_str)

        # List of configuration directives that should be skipped (not rules)
        config_directives = {
            "SecRuleEngine",
            "SecRequestBodyAccess",
            "SecResponseBodyAccess",
            "SecRequestBodyLimit",
            "SecRequestBodyNoFilesLimit",
            "SecRequestBodyLimitAction",
            "SecResponseBodyLimit",
            "SecTmpDir",
            "SecDataDir",
            "SecDebugLog",
            "SecDebugLogLevel",
            "SecAuditEngine",
            "SecAuditLog",
            "SecAuditLogType",
            "SecAuditLogFormat",
            "SecAuditLogParts",
            "SecAuditLogRelevantStatus",
            "SecArgumentSeparator",
            "SecCookieFormat",
            "SecUnicodeMapFile",
            "SecStatusEngine",
            "SecServerSignature",
            "SecComponentSignature",
            "SecUploadDir",
            "SecUploadKeepFiles",
            "SecUploadFileMode",
            "SecCollectionTimeout",
            "SecHttpBlKey",
            "SecGeoLookupDB",
            "SecPcreMatchLimit",
            "SecPcreMatchLimitRecursion",
            "SecWebAppId",
            "SecSensorId",
            "SecHashEngine",
            "SecHashKey",
            "SecHashParam",
            "SecHashMethodRx",
            "SecHashMethodPm",
            "SecGsbLookupDb",
            "SecGuardianLog",
            "SecInterceptOnError",
            "SecConnEngine",
            "SecConnReadStateLimit",
            "SecConnWriteStateLimit",
            "SecRemoteRules",
            "SecRemoteRulesFailAction",
            "SecAction",
            "SecMarker",
            "Include",
            "IncludeOptional",
        }

        # Check if this is a configuration directive (not a rule)
        stripped = normalized_rule.strip()
        for directive in config_directives:
            if stripped.startswith(directive):
                # Skip configuration directives with a debug message
                # In a real implementation, you might want to process these
                logger = logging.getLogger(__name__)
                logger.debug(f"Skipping configuration directive: {directive}")
                return  # Skip this line, don't add a rule

        parts = normalized_rule.split('"')
        if len(parts) < 5 or not parts[0].strip().startswith("SecRule"):
            msg = f"Invalid rule format: {rule_str}"
            raise ValueError(msg)

        variables_str = parts[0].replace("SecRule", "").strip()
        operator_str = parts[1]
        actions_str = parts[3]

        parsed_vars: list[VariableSpec] = []
        for var in variables_str.split("|"):
            var = var.strip()
            # Check for negation (!)
            is_negation = var.startswith("!")
            if is_negation:
                var = var[1:]
            # Check for count (&)
            is_count = var.startswith("&")
            if is_count:
                var = var[1:]

            if ":" in var:
                var_name, key = var.split(":", 1)
                parsed_vars.append(
                    VariableSpec(var_name.upper(), key, is_count, is_negation)
                )
            else:
                parsed_vars.append(
                    VariableSpec(var.upper(), None, is_count, is_negation)
                )

        # Handle negated operators like !@rx
        negated = False
        if operator_str.startswith("!"):
            negated = True
            operator_str = operator_str[1:]

        if operator_str.startswith("@"):
            parts = operator_str[1:].split(" ", 1)
            op_name = parts[0]
            op_arg = parts[1] if len(parts) > 1 else ""
        else:
            op_name, op_arg = "rx", operator_str

        try:
            options = OperatorOptions(op_arg)
            op_instance = get_operator(op_name, options)
            parsed_operator = ParsedOperator(op_name, op_arg, op_instance, negated)
        except ValueError as e:
            msg = f"Failed to create operator {op_name}: {e}"
            raise ValueError(msg) from e

        parsed_actions: dict[str, Any] = {}
        parsed_transformations: list[str] = []
        parsed_metadata: dict[str, int | str] = {}
        tags: list[str] = []

        # Split actions properly, respecting quoted values
        actions = self._split_actions(actions_str)

        for action in actions:
            action = action.strip()
            key, _, value = action.partition(":")
            key = key.lower()

            if key == "t":
                parsed_transformations.append(value)
            else:
                action_class = ACTIONS.get(key)
                if not action_class:
                    msg = f"Unknown action: {key}"
                    raise ValueError(msg)
                parsed_actions[key] = action_class(value)
                if key in {"id", "phase"}:
                    parsed_metadata[key] = int(value)
                if key == "tag":
                    tags.append(value)

        for key, action in parsed_actions.items():
            action.init(parsed_metadata, action.argument or "")

        rule = Rule(
            parsed_vars,
            parsed_operator,
            parsed_transformations,
            parsed_actions,
            parsed_metadata,
            tags,
        )
        self.rule_group.add(rule)


class WAF:
    """Web Application Firewall instance.

    Public API (stable for 1.0):
        new_transaction() -> Transaction - Create a new transaction

    Internal API (may change between versions):
        rule_group, parser, component_signature, rule_engine_mode,
        request_body_access, response_body_access

    Example:
        waf = WAF({"rules": ['SecRule ARGS "@rx attack" "id:1,phase:1,deny"']})
        tx = waf.new_transaction()
        tx.process_uri("/api", "GET")
        result = tx.process_request_headers()
    """

    def __init__(self, config: dict[str, list[Any] | list[str]]):
        self.rule_group = RuleGroup()
        self.parser = SecLangParser(self.rule_group)
        self.component_signature: str = ""

        # File parser for config["rule_files"] (globs, Include, etc.)
        self.file_parser = FileSecLangParser(self)
        # Configuration directives (set by parser or programmatically)
        self.rule_engine_mode: str = "on"  # on, off, detectiononly
        self.request_body_access: bool = True
        self.response_body_access: bool = False

        for rule_str in config["rules"]:
            self.parser.from_string(rule_str)
        for pattern in config.get("rule_files", []):
          self.file_parser.from_file(pattern)

    def new_transaction(self) -> Transaction:
        """Create a new transaction with a unique ID.

        Returns:
            A new Transaction instance with a UUID-based identifier.
        """
        return Transaction(self, f"tx-{uuid.uuid4().hex[:12]}")
