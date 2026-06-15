"""
SQL Injection detection plugin.

Detection techniques:
- Error-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection

Multiple detection signals increase finding confidence and may
allow database fingerprinting.
"""

from __future__ import annotations


from difflib import SequenceMatcher

from sentinel.core.context import ScanContext
from sentinel.core.http_client import Response
from sentinel.models import (Confidence, Evidence, Finding, Form, Severity)
from sentinel.plugins.base import Plugin


import re
from enum import Enum



from urllib.parse import quote

class Dbms(str, Enum):
    MYSQL = "MySQL"
    POSTGRES = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    UNKNOWN = "Unknown"


_ERROR_SIGNATURES: dict[Dbms, list[str]] = {
    Dbms.MYSQL: [r"sql syntax.*mysql", r"warning.*mysqli?", r"valid mysql result",
                 r"you have an error in your sql syntax"],
    Dbms.POSTGRES: [r"postgresql.*error", r"pg_query\(\)", r"unterminated quoted string",
                    r"pg::syntaxerror"],
    Dbms.MSSQL: [r"microsoft sql server", r"odbc sql server driver",
                 r"unclosed quotation mark after the character string",
                 r"incorrect syntax near"],
    Dbms.ORACLE: [r"\bora-\d{5}", r"oracle.*driver", r"quoted string not properly terminated"],
    Dbms.SQLITE: [r"sqlite3?::", r"sqlite_error", r"unrecognized token"],
}


def fingerprint_from_error(text: str) -> Dbms:
    low = text.lower()
    for dbms, patterns in _ERROR_SIGNATURES.items():
        if any(re.search(p, low) for p in patterns):
            return dbms
    return Dbms.UNKNOWN


def has_sql_error(text: str) -> bool:
    return fingerprint_from_error(text) is not Dbms.UNKNOWN


def time_payload(dbms: Dbms, seconds: int = 5) -> str:
    return {
        Dbms.MYSQL: f"1' OR IF(1=1,SLEEP({seconds}),0)#",
        Dbms.POSTGRES: f"' OR pg_sleep({seconds})-- -",
        Dbms.MSSQL: f"'; WAITFOR DELAY '0:0:{seconds}'-- -",
        Dbms.ORACLE: f"' OR dbms_pipe.receive_message('a',{seconds})-- -",
        Dbms.SQLITE: f"' OR randomblob(100000000)-- -",  # SQLite has no sleep
        Dbms.UNKNOWN: f"' OR SLEEP({seconds})-- -",
    }[dbms]

def mutations(payload: str) -> list[str]:
    """
    Generate common payload encodings.

    Example:
        '
        %27
        %2527
    """
    return [
        payload,
        quote(payload),
        quote(quote(payload)),
    ]


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


class SqliPlugin(Plugin):
    id = "sqli"
    name = "SQL Injection"
    default_severity = Severity.HIGH

    aggressive = False


    ERROR_PAYLOADS = [
        "'",
        "\"",
        "')",
        '")',
        "' OR '1'='1",
    ]

    BOOLEAN_TRUE_PAYLOADS = [
        "' OR 1=1-- -",
        "' OR 'a'='a'-- -",
        "1' OR 1=1#",
        "1') OR ('1'='1",
    ]

    BOOLEAN_FALSE_PAYLOADS = [
        "' AND 1=2-- -",
        "' AND 'a'='b'-- -",
        "1' AND 1=2#",
        "1') AND ('1'='2",
    ]

    DANGEROUS_FIELDS = {
        "password_new",
        "password_conf",
        "create_db",
        "delete",
        "remove",
        "reset",
    }

    IGNORE_FIELDS = {
        "submit",
        "user_token",
        "csrf",
        "token",
        "submit_button",
        "action",
        "search_type",
    }
    

    def _is_dangerous_form(self, form: Form) -> bool:
        names = {i.name.lower() for i in form.inputs}
        return bool(names & self.DANGEROUS_FIELDS)

    async def run(self, ctx: ScanContext, form: Form) -> None:
        if self._is_dangerous_form(form):
            return

        for param in form.fuzzable_params:
            if param.lower() in self.IGNORE_FIELDS:
                continue

            await self._test_param(ctx, form, param)

    async def _test_param(self, ctx: ScanContext, form: Form, param: str) -> None:
        base_data = form.baseline_data()
        baseline = await self._send(ctx, form, base_data)

        signals: list[str] = []
        dbms = Dbms.UNKNOWN
        evidence: list[Evidence] = []

        # Error-based detection
        for payload in self.ERROR_PAYLOADS:
            for variant in mutations(payload):

                

                err_data = dict(base_data)
                err_data[param] = variant

                err_resp = await self._send(ctx, form, err_data)

                if (
                    has_sql_error(err_resp.text)
                    and not has_sql_error(baseline.text)
                ):

                    dbms = fingerprint_from_error(err_resp.text)

                    signals.append("error-based")

                    evidence.append(
                        Evidence(
                            description=(
                                f"Database error provoked by payload "
                                f"'{variant}' "
                                f"(fingerprint: {dbms.value})."
                            ),
                            request=variant,
                            response_excerpt=self._error_excerpt(err_resp.text),
                        )
                    )

                    break

            if "error-based" in signals:
                break

            

        # Boolean-based detection
        for true_payload, false_payload in zip(
            self.BOOLEAN_TRUE_PAYLOADS,
            self.BOOLEAN_FALSE_PAYLOADS,
        ):

            found = False

            for true_variant in mutations(true_payload):
                for false_variant in mutations(false_payload):

                    true_data = dict(base_data)
                    true_data[param] = true_variant

                    false_data = dict(base_data)
                    false_data[param] = false_variant

                    r_true = await self._send(ctx, form, true_data)
                    r_false = await self._send(ctx, form, false_data)

                    sim_true = similarity(
                        baseline.text,
                        r_true.text,
                    )

                    sim_false = similarity(
                        baseline.text,
                        r_false.text,
                    )

                    if (
                        sim_true > 0.95
                        and sim_false < 0.90
                        and (sim_true - sim_false) > 0.08
                    ):

                        signals.append("boolean-based")

                        evidence.append(
                            Evidence(
                                description=(
                                    "Boolean condition changed the response: "
                                    f"sim(true)={sim_true:.2f}, "
                                    f"sim(false)={sim_false:.2f}."
                                ),
                                request=(
                                    f"true:{true_variant} / "
                                    f"false:{false_variant}"
                                ),
                            )
                        )

                        found = True
                        break

                if found:
                    break

            if found:
                break   

        
        # Time-based blind detection (aggressive mode only)
        if ctx.scope.allow_aggressive:
            if await self._time_based(ctx, form, param, base_data, dbms):
                if "time-based blind" not in signals:
                    signals.append("time-based blind")

                evidence.append(
                    Evidence(
                        description=(
                            "Response delayed in proportion to an injected "
                            "time-delay function, confirmed over two trials."
                        ),
                    )
                )
        
        if not signals:
            return

        if len(signals) >= 2:
            confidence = Confidence.CONFIRMED
        elif "time-based blind" in signals:
            confidence = Confidence.CONFIRMED
        else:
            confidence = Confidence.FIRM

        method = " + ".join(signals)

        detected_payload = ""

        for ev in evidence:
            if getattr(ev, "request", None):
                detected_payload = ev.request
                break

        ctx.report(
            Finding(
                name="SQL Injection",
                plugin=self.id,
                severity=Severity.HIGH,
                confidence=confidence,
                cwe="CWE-89",
                cvss=8.6,

                url=form.action,
                parameter=param,
                method=form.method,

                payload=detected_payload,

                database=(
                    dbms.value
                    if dbms is not Dbms.UNKNOWN
                    else None
                ),

                techniques=signals,

                
                description=(
                    f"Parameter '{param}' appears vulnerable to SQL Injection. "
                    f"Detection techniques: {', '.join(signals)}."
                    + (
                        f" Backend database appears to be {dbms.value}."
                        if dbms is not Dbms.UNKNOWN
                        else ""
                    )
                ),

                remediation=(
                    "Use parameterised queries / prepared statements for all "
                    "database access. Apply least-privilege DB accounts and "
                    "validate/normalise input. Never concatenate user input "
                    "into SQL."
                ),

                reproduction=[
                    f"Send a {form.method} request to {form.action}",
                    f"Inject payloads into parameter '{param}'",
                    "Observe SQL errors, response differences, or time delays",
                ],

                evidence=evidence,
            )
        )
    async def _time_based(
        self,
        ctx: ScanContext,
        form: Form,
        param: str,
        base_data: dict[str, str],
        dbms: Dbms,
    ) -> bool:
        ctx.scope.assert_aggressive_allowed("time-based blind SQLi")

        delay = 5
        payload = time_payload(dbms, delay)

        data = dict(base_data)
        data[param] = payload

        try:
            first = await self._timed(ctx, form, data)
        except RuntimeError as e:
            if "ReadTimeout" in str(e):
                return True
            raise

        if first < delay * 0.8:
            return False

        second = await self._timed(ctx, form, data)
        base = await self._timed(ctx, form, base_data)

        return second >= delay * 0.8 and base < delay * 0.5

    async def _timed(
        self,
        ctx: ScanContext,
        form: Form,
        data: dict[str, str],
    ) -> float:
        resp = await self._send(ctx, form, data)
        return resp.elapsed

    async def _send(
        self,
        ctx: ScanContext,
        form: Form,
        data: dict[str, str],
    ) -> Response:
        if form.method == "POST":
            return await ctx.http.post(
                form.action,
                data=data,
                use_cache=False,
            )

        return await ctx.http.get(
            form.action,
            params=data,
            use_cache=False,
        )

    @staticmethod
    def _error_excerpt(text: str) -> str:
        low = text.lower()

        for kw in ("sql", "syntax", "ora-", "sqlite", "postgres"):
            i = low.find(kw)
            if i >= 0:
                return text[max(0, i - 30):i + 90]

        return text[:120]