# src/lewaf/seclang/parser.py
"""SecLang parser backed by msc_pyparser.

msc_pyparser tokenizes SecLang (the same parser the OWASP CRS project uses),
and this module walks its AST to:

* dispatch SecRule nodes to ``SecRuleParser``,
* route ``SecX`` directives to ``_handle_secX`` methods,
* resolve Include / IncludeOptional chains,
* populate WAF configuration attributes (rule_engine_mode, body access, ...).

The public surface mirrors the original hand-written parser: ``default_actions``,
``markers``, ``current_file``/``current_dir``/``current_line``, ``include_count``,
and ``_handle_*`` methods for each directive.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import msc_pyparser

from lewaf.exceptions import IncludeRecursionError, ParseError

if TYPE_CHECKING:
    from lewaf.integration import WAF

logger = logging.getLogger(__name__)

# Directives msc_pyparser's lexer rejects but CRS/coraza configs contain.
# We skip these lines rather than letting the lexer abort the whole file.
_MSC_UNSUPPORTED = frozenset({
    "secrequestbodyinmemorylimit",
    # add more as they surface
})

class SecLangParser:
    """Parser for ModSecurity SecLang configuration files."""

    MAX_INCLUDE_RECURSION = 100

    def __init__(self, waf: "WAF") -> None:
        self.waf = waf

        # Rule parsing is delegated to SecRuleParser, which knows how to turn
        # an msc_pyparser SecRule node into a Rule.
        from lewaf.seclang.rule_parser import SecRuleParser
        self.rule_parser = SecRuleParser(self)

        # Context tracking (mirrors the original parser)
        self.current_line = 0
        self.current_file = ""
        self.current_dir = ""
        self.include_count = 0
        self._include_depth = 0

        # Default actions per phase (public — tests read this)
        self.default_actions: dict[int, str] = {
            2: "phase:2,log,auditlog,pass",
        }

        # Marker registry (name -> rule index / id)
        self.markers: dict[str, int] = {}

        # msc_pyparser instance reused across parse calls
        self._msc_parser = msc_pyparser.MSCParser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def from_file(self, file_path: str | Path) -> None:
        path = Path(file_path)
        if any(ch in str(path) for ch in "*?["):
            matches = sorted(path.parent.glob(path.name))
            if not matches:
                logger.warning("No files matching pattern: %s", file_path)
                return
            for f in matches:
                self._parse_single_file(f)
        else:
            self._parse_single_file(path)
    def _prefilter(self, content: str) -> str:
        out = []
        for line in content.splitlines():
            stripped = line.lstrip()
            head = stripped.split(None, 1)[0].lower() if stripped else ""
            if head in _MSC_UNSUPPORTED:
                logger.debug("Pre-filtering unsupported directive: %s", stripped)
                out.append(f"# {line}")  # comment out to preserve line numbers
            else:
                out.append(line)
        return "\n".join(out)

    def from_string(self, content: str, base_dir: Path | None = None) -> None:
        if not self.current_file:
            self.current_file = ""

        parser = msc_pyparser.MSCParser()
        try:
            parser.parser.parse(self._prefilter(content))
        except Exception as exc:  # noqa: BLE001
            raise ParseError(
                f"msc_pyparser failed: {exc}",
                file_path=self.current_file,
                line_number=self.current_line,
            ) from exc

        self._dispatch(parser.configlines or [], base_dir=base_dir)

    # ------------------------------------------------------------------
    # File handling
    # ------------------------------------------------------------------

    def _parse_single_file(self, file_path: Path) -> None:
        old_file, old_dir, old_line = (
            self.current_file,
            self.current_dir,
            self.current_line,
        )
        try:
            self.current_file = str(file_path)
            self.current_dir = str(file_path.parent)
            self.current_line = 0

            try:
                content = file_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise ParseError(
                    f"Cannot read {file_path}: {exc}",
                    file_path=str(file_path),
                ) from exc

            logger.info("Parsing SecLang file: %s", file_path)
            self.from_string(content, base_dir=file_path.parent)
        finally:
            self.current_file = old_file
            self.current_dir = old_dir
            self.current_line = old_line

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------


    def _dispatch(self, configlines, base_dir=None):
        for item in configlines:
            kind = item.get("type")
            if not kind or kind == "Comment":
                continue
            if kind == "SecRule":
                self.rule_parser.parse_rule_from_msc(item)
            elif kind == "SecAction":
                self._handle_secaction_node(item)
            else:
                # Include, SecMarker, SecRuleEngine, SecDefaultAction, ...
                # _handle_directive reads the name from either node["directive"]
                # or node["type"], so this covers both AST shapes.
                self._handle_directive(item, base_dir)

    def _handle_directive(
        self, node: dict[str, Any], base_dir: Path | None
    ) -> None:
        name, args = self._normalize_directive(node)
        if not name:
            return

        # Route to a _handle_<name> method if we have one.
        handler_name = f"_handle_{name.replace('-', '_')}"
        handler: Callable | None = getattr(self, handler_name, None)
        if handler is not None:
            try:
                handler(args, base_dir=base_dir)
            except TypeError:
                # Some handlers don't take base_dir; fall back to one-arg call.
                handler(args)
            return

        logger.debug("Ignoring directive %s %r", name, args)

    # ------------------------------------------------------------------
    # Directive handlers
    # ------------------------------------------------------------------

    def _handle_include(self, args: Any, base_dir: Path | None = None) -> None:
        patterns = args if isinstance(args, list) else [args]
        if self.include_count >= self.MAX_INCLUDE_RECURSION:
            raise IncludeRecursionError(
                file_path=self.current_file,
                depth=self.include_count,
                max_depth=self.MAX_INCLUDE_RECURSION,
            )

        self.include_count += 1
        try:
            for pattern in patterns:
                if not pattern:
                    continue
                target = Path(pattern)
                if not target.is_absolute():
                    base = base_dir or Path(self.current_dir or ".")
                    target = base / target
                self.from_file(target)
        finally:
            self.include_count -= 1

    # Alias: some msc_pyparser versions surface this as "includeoptional".
    _handle_includeoptional = _handle_include

    def _handle_secruleengine(self, args: Any, base_dir: Path | None = None) -> None:
        mode = self._first_arg(args).lower()
        logger.info("Setting rule engine to: %s", mode)
        self.waf.rule_engine_mode = mode

    def _handle_secrequestbodyaccess(
        self, args: Any, base_dir: Path | None = None
    ) -> None:
        enabled = self._first_arg(args).lower() == "on"
        logger.info("Request body access: %s", enabled)
        self.waf.request_body_access = enabled

    def _handle_secresponsebodyaccess(
        self, args: Any, base_dir: Path | None = None
    ) -> None:
        enabled = self._first_arg(args).lower() == "on"
        logger.info("Response body access: %s", enabled)
        self.waf.response_body_access = enabled

    def _handle_secdefaultaction(
        self, args: Any, base_dir: Path | None = None
    ) -> None:
        action_string = self._first_arg(args)
        # Parse phase out of the action string; default to phase 2.
        import re
        m = re.search(r"phase:(\d+)", action_string)
        phase = int(m.group(1)) if m else 2
        self.default_actions[phase] = action_string
        # Also feed SecRuleParser so rules inherit these defaults.
        try:
            self.rule_parser.set_default_action(action_string)
        except Exception as exc:  # noqa: BLE001
            logger.debug("SecDefaultAction parsing failed: %s", exc)
        logger.info("Set default actions for phase %s: %s", phase, action_string)

    def _handle_secmarker(self, args: Any, base_dir: Path | None = None) -> None:
        marker_name = self._first_arg(args).strip().strip('"').strip("'")
        if not marker_name:
            logger.warning(
                "SecMarker with empty name at %s:%s",
                self.current_file,
                self.current_line,
            )
            return
        # Synthesize a real Rule so tests and skipAfter can find it.
        self._register_marker_rule(marker_name)
        logger.debug("Registered marker '%s'", marker_name)

    def _handle_seccomponentsignature(
        self, args: Any, base_dir: Path | None = None
    ) -> None:
        signature = self._first_arg(args).strip().strip('"').strip("'")
        logger.info("Component signature: %s", signature)
        self.waf.component_signature = signature

    # ------------------------------------------------------------------
    # SecAction handling
    # ------------------------------------------------------------------

    def _handle_secaction_node(self, node: dict[str, Any]) -> None:
        """SecAction reached _dispatch; delegate to rule_parser, which
        knows how to synthesize a Rule from action-only AST nodes."""
        self.rule_parser.parse_secaction_from_msc(node)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _register_marker_rule(self, marker_name: str) -> None:
        """Create a synthetic rule that tags itself with the marker name."""
        from lewaf.rules import Rule, VariableSpec
        from lewaf.integration import ParsedOperator

        rule = Rule(
            variables=[VariableSpec(name="REQUEST_METHOD")],
            operator=ParsedOperator(
                op=None, name="unconditionalmatch", argument="", negated=False
            ),
            transformations=[],
            actions={},
            metadata={"id": self._next_marker_id(), "phase": 1},
            tags=[marker_name],
        )
        self.waf.rule_group.add(rule)
        self.markers[marker_name] = len(self.waf.rule_group.rules_by_phase[1]) - 1

    def _next_marker_id(self) -> int:
        # Marker IDs go in a reserved range so they don't collide with CRS IDs.
        return 8_000_000 + len(self.markers)

    @staticmethod
    def _first_arg(args: Any) -> str:
        if isinstance(args, list):
            return str(args[0]) if args else ""
        return str(args or "")

    @staticmethod
    def _normalize_directive(node: dict[str, Any]) -> tuple[str, list[str]]:
        """Return (lowercase directive name, list of string arguments)."""
        name = node.get("directive") or node.get("type") or ""
        name = str(name).lower()

        args: list[str] = []
        for a in node.get("arguments") or []:
            if isinstance(a, str):
                args.append(a)
            elif isinstance(a, dict):
                val = a.get("argument") or a.get("arg") or ""
                args.append(str(val))
        return name, args


__all__ = ["SecLangParser", "ParseError"]
