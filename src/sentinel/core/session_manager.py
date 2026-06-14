
"""Authentication / session manager."""
from __future__ import annotations

from bs4 import BeautifulSoup

from sentinel.core.config import AuthConfig
from sentinel.core.http_client import HttpClient
from sentinel.logging_setup import log


class SessionManager:
    def __init__(self, auth: AuthConfig) -> None:
        self._auth = auth

    async def authenticate(self, http: HttpClient) -> None:
        kind = self._auth.type

        if kind == "none":
            return

        if kind == "cookie":
            http.set_auth(headers=None, cookies=self._auth.cookies)
            log.info("applied cookie authentication")

        elif kind == "bearer":
            if not self._auth.token:
                raise ValueError("bearer auth requires a token")

            http.set_auth(
                headers={"Authorization": f"Bearer {self._auth.token}"},
                cookies=None,
            )
            log.info("applied bearer-token authentication")

        elif kind == "header":
            http.set_auth(headers=self._auth.headers, cookies=None)
            log.info("applied custom-header authentication")

        elif kind == "form":
            await self._form_login(http)

        else:
            raise ValueError(f"unknown auth type: {kind}")

    async def _form_login(self, http: HttpClient) -> None:
        if not self._auth.login_url:
            raise ValueError("form auth requires login_url")

        resp = await http.get(self._auth.login_url)
        soup = BeautifulSoup(resp.text, "html.parser")

        payload: dict[str, str] = {}

        for hidden in soup.find_all("input", {"type": "hidden"}):
            name = hidden.get("name")
            if name:
                payload[name] = hidden.get("value", "")

        payload[self._auth.username_field] = self._auth.username or ""
        payload[self._auth.password_field] = self._auth.password or ""
        payload["Login"] = "Login"

    

        login_resp = await http.post(
        self._auth.login_url,
        data=payload,
        use_cache=False,
        )

        

        success_markers = (
            "logout",
            "dvwa security",
            "welcome :: damn vulnerable web application",
        )

        if any(marker in login_resp.text.lower() for marker in success_markers):
            log.info("Authentication successful")
        else:
            log.warning("Login may have failed")

        hidden_count = sum(
            1
            for k in payload
            if k not in (
                self._auth.username_field,
                self._auth.password_field,
                "Login",
            )
        )

        log.info(
            f"submitted form login as '{self._auth.username}' "
            f"({len(payload)} fields, {hidden_count} hidden/token)"
        )
