# src/lewaf/seclang/rule_parser.py
"""Build LeWAF Rule objects from msc_pyparser AST nodes."""
from __future__ import annotations

import logging
from itertools import count
from typing import Any

from lewaf.exceptions import ParseError
from lewaf.primitives.actions import ACTIONS, Action
from lewaf.rules import Rule, VariableSpec

logger = logging.getLogger(__name__)


# IDs auto-assigned to SecRule/SecAction/SecMarker when none is provided.
_AUTO_ID = count(9_000_001)


class SecRuleParser:
    def __init__(self, parser) -> None:
        self.parser = parser
        self._default_actions: dict[str, Action] = {}

    # ------------------------------------------------------------------
    # SecDefaultAction
    # ------------------------------------------------------------------

    def set_default_action(self, action_string: str) -> None:
        _, actions, _ = self._parse_actions(
            self._split_action_string(action_string)
        )
        self._default_actions = actions

    # ------------------------------------------------------------------
    # SecRule
    # ------------------------------------------------------------------

    def parse_rule_from_msc(self, node: dict[str, Any]) -> None:
        variables_raw = node.get("variables") or []
        operator_raw = node.get("operator") or ""
        operator_arg = node.get("operator_argument") or ""

        # A rule is malformed when it has no variables at all, or when it has
        # neither an operator name nor an argument. "SecRule ARGS" (bare) lands
        # here; 'SecRule ARGS "^x"' does not, because operator_argument is set.
        if not variables_raw or (not operator_raw and not operator_arg):
            raise ParseError(
                "Invalid SecRule format: missing variables or operator",
                file_path=getattr(self.parser, "current_file", None),
                line_number=node.get("lineno"),
            )

        # --- everything below is now OUTSIDE the if ---
        transformations, own_actions, metadata = self._parse_actions(
            node.get("actions") or []
        )
        metadata.setdefault("id", next(_AUTO_ID))
        metadata.setdefault("phase", 2)

        rule = Rule(
            variables=self._build_variables(variables_raw),
            operator=self._build_operator(node),
            transformations=transformations,
            actions={**self._default_actions, **own_actions},
            metadata=metadata,
            tags=[],
        )
        self.parser.waf.rule_group.add(rule)


    # ------------------------------------------------------------------
    # SecAction
    # ------------------------------------------------------------------

    def parse_secaction_from_msc(self, node: dict[str, Any]) -> None:
        """Synthesize a Rule that unconditionally runs its actions.

        The LeWAF engine has no dedicated SecAction path yet, so we register
        a Rule with an always-matching operator. When RuleGroup grows real
        SecAction support this method will be replaced; until then, this
        gives CRS scoring rules something to evaluate against.
        """
        from lewaf.integration import ParsedOperator

        _, actions, metadata = self._parse_actions(node.get("actions") or [])
        metadata.setdefault("id", next(_AUTO_ID))
        metadata.setdefault("phase", 2)

        rule = Rule(
            variables=[VariableSpec(name="REQUEST_METHOD")],
            operator=ParsedOperator(
                op=None,
                name="unconditionalmatch",
                argument="",
                negated=False,
            ),
            transformations=[],
            actions={**self._default_actions, **actions},
            metadata=metadata,
            tags=[],
        )
        self.parser.waf.rule_group.add(rule)

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def _build_variables(self, raw: list[dict]) -> list[VariableSpec]:
        out = []
        for v in raw:
            name = v.get("variable") or ""
            if not name:
                continue
            out.append(VariableSpec(
                name=name,
                key=v.get("variable_part") or None,
                is_count=bool(v.get("counter", False)),
                is_negation=bool(v.get("negated", False)),
            ))
        return out

    def _build_operator(self, node: dict):
        """Build a ParsedOperator.

        The kernel looks operator names up in a lowercase registry keyed
        WITHOUT the leading '@' (e.g. 'rx', 'detectsqli'). msc_pyparser
        hands us '@rx', '@detectSQLi'. Normalize both here.
        """
        from lewaf.integration import ParsedOperator

        raw = node.get("operator", "") or ""
        argument = self._strip_quotes(node.get("operator_argument", "") or "")
        negated = bool(node.get("operator_negated", False))

        # Bare regex: msc_pyparser puts the pattern in operator_argument and
        # leaves operator empty. ModSecurity treats this as an implicit @rx.
        if not raw and argument:
            raw = "@rx"

        name = raw[1:].lower() if raw.startswith("@") else raw.lower()
        return ParsedOperator(op=None, name=name, argument=argument, negated=negated)

    def _parse_actions(self, raw: list[Any]):
        transformations: list[str] = []
        actions: dict[str, Action] = {}
        metadata: dict[str, int | str] = {}

        # Pass 1: collect id/phase so init() can see them.
        for entry in raw:
            name, arg = self._normalize_action_entry(entry)
            lname = name.lower()
            if lname in ("id", "phase"):
                metadata[lname] = int(arg) if arg.isdigit() else arg

        # Pass 2: construct and init each action.
        for entry in raw:
            name, arg = self._normalize_action_entry(entry)
            if not name:
                continue
            lname = name.lower()

            if lname == "t":
                if arg:
                    transformations.append(arg)
                continue

            cls = ACTIONS.get(lname)
            if cls is None:
                logger.debug("Unknown action %r (arg=%r); ignoring", lname, arg)
                continue

            try:
                action = cls(arg)
                action.init(metadata, arg)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Dropping action %s(arg=%r): %s", lname, arg, exc)
                continue

            actions[lname] = action

        return transformations, actions, metadata

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_quotes(s: str) -> str:
        if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
            return s[1:-1]
        return s

    @staticmethod
    def _normalize_action_entry(entry: Any) -> tuple[str, str]:
        """Return (name, argument) from an msc_pyparser action node.

        msc_pyparser splits `name=value` across act_arg / act_arg_val.
        """
        if isinstance(entry, str):
            return SecRuleParser._split_action_token(entry)
        if not isinstance(entry, dict):
            return "", ""

        name = str(entry.get("act_name") or entry.get("action") or "").strip()
        left = SecRuleParser._strip_quotes(str(entry.get("act_arg") or ""))
        right = SecRuleParser._strip_quotes(str(entry.get("act_arg_val") or ""))
        if right:
            return name, f"{left}={right}"
        return name, left

    @staticmethod
    def _split_action_token(token: str) -> tuple[str, str]:
        token = token.strip()
        if not token:
            return "", ""
        if ":" in token:
            name, _, arg = token.partition(":")
            return name.strip(), SecRuleParser._strip_quotes(arg.strip())
        return token, ""

    @staticmethod
    def _split_action_string(action_string: str) -> list[str]:
        return [t.strip() for t in action_string.split(",") if t.strip()]
