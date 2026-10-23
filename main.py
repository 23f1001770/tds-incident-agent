from starlette.concurrency import run_in_threadpool
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from planner import plan_incident

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "incidents.db")))
PROFILE = "ga5-incident-agent/v2"
DESTRUCTIVE_TOOLS = {"rollback_deployment", "disable_feature"}

app = FastAPI(title="TDS Public HTTPS Incident Agent", version="2.0.0")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def new_id(byte_count=16):
    while True:
        value = secrets.token_hex(byte_count)
        if set(value) != {"0"}:
            return value


def opaque_id():
    return secrets.token_hex(16)


@contextmanager
def database():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database():
    with database() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                run_id TEXT PRIMARY KEY,
                request_json TEXT NOT NULL,
                state_json TEXT NOT NULL,
                internal_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                response_json TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES incidents(run_id)
            )
        """)
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(incidents)").fetchall()
        }
        if "internal_json" not in columns:
            db.execute(
                "ALTER TABLE incidents ADD COLUMN internal_json TEXT NOT NULL DEFAULT '{}'"
            )
        receipt_columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(receipts)").fetchall()
        }
        if "response_json" not in receipt_columns:
            db.execute(
                "ALTER TABLE receipts ADD COLUMN response_json TEXT NOT NULL DEFAULT '{}'"
            )


initialize_database()


def store_state(run_id, state, internal):
    with database() as db:
        db.execute(
            "UPDATE incidents SET state_json=?, internal_json=? WHERE run_id=?",
            (canonical(state), canonical(internal), run_id),
        )


def load_incident(run_id):
    with database() as db:
        row = db.execute(
            "SELECT request_json,state_json,internal_json FROM incidents WHERE run_id=?",
            (run_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "request": json.loads(row["request_json"]),
        "state": json.loads(row["state_json"]),
        "internal": json.loads(row["internal_json"]),
    }


def valid_trace_context(traceparent):
    if not isinstance(traceparent, str):
        return None
    match = re.fullmatch(
        r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})",
        traceparent,
    )
    if not match:
        return None
    trace_id, parent_id, flags = match.groups()
    if set(trace_id) == {"0"} or set(parent_id) == {"0"}:
        return None
    return trace_id, parent_id, flags


def attr(key, value):
    if isinstance(value, bool):
        typed = {"boolValue": value}
    elif isinstance(value, int):
        typed = {"intValue": str(value)}
    elif isinstance(value, float):
        typed = {"doubleValue": value}
    else:
        typed = {"stringValue": str(value)}
    return {"key": key, "value": typed}


def span(trace_id, span_id, parent_id, name, kind, attributes,
         start_ns=None, end_ns=None, status_code=0, links=None):
    now = time.time_ns()
    result = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start_ns or now),
        "endTimeUnixNano": str(end_ns or now + 1),
        "attributes": attributes,
        "status": {"code": status_code},
    }
    if parent_id:
        result["parentSpanId"] = parent_id
    if links:
        result["links"] = links
    return result


def span_attr_list(run_id, marker, extra=None):
    result = [
        attr("ga5.run.id", run_id),
        attr("ga5.public.marker", marker),
    ]
    if extra:
        result.extend(attr(key, value) for key, value in extra.items())
    return result


def make_trace_context(headers):
    incoming = valid_trace_context(headers.get("traceparent"))
    if incoming:
        trace_id, parent_id, flags = incoming
        return {
            "traceId": trace_id,
            "remoteParentId": parent_id,
            "traceFlags": flags,
            "tracestate": headers.get("tracestate"),
        }
    return {
        "traceId": new_id(16),
        "remoteParentId": None,
        "traceFlags": "01",
        "tracestate": None,
    }


def build_otlp(spans):
    return {
        "resourceSpans": [{
            "resource": {
                "attributes": [attr("service.name", "tds-incident-agent")]
            },
            "scopeSpans": [{
                "scope": {"name": "tds-incident-agent"},
                "spans": spans,
            }],
        }]
    }


@app.get("/")
def root():
    return {
        "service": "TDS Public HTTPS Incident Agent",
        "version": "2.0.0",
        "status": "running",
    }


@app.get("/health")
def health():
    with database() as db:
        db.execute("SELECT 1").fetchone()
    return {"status": "ok", "database": "ok"}


def extract_evidence_ids(transcript):
    if not isinstance(transcript, str):
        return set()
    return set(re.findall(r"\[([A-Za-z0-9_-]{2,})\]", transcript))


@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "request must be a JSON object"}, status_code=400)
    if body.get("profile") != PROFILE:
        return JSONResponse({"error": "unsupported profile"}, status_code=422)

    run_id = body.get("runId")
    marker = body.get("publicMarker")
    if not isinstance(run_id, str) or len(run_id) < 8:
        return JSONResponse({"error": "invalid runId"}, status_code=422)
    if not isinstance(marker, str) or not marker:
        return JSONResponse({"error": "invalid publicMarker"}, status_code=422)

    for field in ("agentName", "incident", "toolCatalog", "policy"):
        if field not in body:
            return JSONResponse({"error": f"missing field: {field}"}, status_code=422)

    if not isinstance(body["incident"], dict):
        return JSONResponse({"error": "incident must be an object"}, status_code=422)
    if not isinstance(body["toolCatalog"], list):
        return JSONResponse({"error": "toolCatalog must be a list"}, status_code=422)
    if not isinstance(body["policy"], dict):
        return JSONResponse({"error": "policy must be an object"}, status_code=422)

    request_json = canonical(body)

    # Replay returns the stored response and never calls Gemini again.
    existing = load_incident(run_id)
    if existing:
        if canonical(existing["request"]) != request_json:
            return JSONResponse(
                {"error": "runId already used with different request"},
                status_code=409,
            )
        return JSONResponse(existing["state"])

    incident = body["incident"]
    allowed_causes = incident.get("allowedRootCauses")
    if not isinstance(allowed_causes, list) or not allowed_causes:
        return JSONResponse({"error": "invalid allowedRootCauses"}, status_code=422)

    # The planner uses an explicit allowlist and never receives body["sensitive"].
    try:
        plan = await run_in_threadpool(plan_incident, body)
    except Exception as exc:
        print(f"Incident planning failed: {type(exc).__name__}", flush=True)
        return JSONResponse(
            {"error": "incident planning failed safely"},
            status_code=502,
        )

    catalog = body["toolCatalog"]
    catalog_by_name = {
        tool.get("name"): tool
        for tool in catalog
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }
    policy = body["policy"]
    maximum = policy.get("maximumDiagnostics", 1)
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        return JSONResponse({"error": "invalid maximumDiagnostics"}, status_code=422)

    transcript_ids = extract_evidence_ids(incident.get("transcript", ""))
    diagnosis_ids = plan.get("evidenceIds")
    if (
        not isinstance(diagnosis_ids, list)
        or not 2 <= len(diagnosis_ids) <= 4
        or len(set(diagnosis_ids)) != len(diagnosis_ids)
        or any(not isinstance(e, str) or e not in transcript_ids for e in diagnosis_ids)
    ):
        return JSONResponse({"error": "invalid diagnosis evidence"}, status_code=422)

    if plan.get("rootCause") not in allowed_causes:
        return JSONResponse({"error": "invalid diagnosis"}, status_code=422)

    proposed = plan.get("diagnostics", [])
    if not isinstance(proposed, list):
        return JSONResponse({"error": "invalid diagnostic plan"}, status_code=422)

    safe_diagnostics = []
    for item in proposed:
        if len(safe_diagnostics) >= min(maximum, 3):
            break
        if not isinstance(item, dict):
            continue
        name = item.get("toolName")
        arguments = item.get("arguments")
        cited = item.get("evidenceIds")
        tool = catalog_by_name.get(name)
        if not tool or not isinstance(arguments, dict) or not isinstance(cited, list):
            continue
        if name in set(policy.get("effectTools", [])):
            continue
        if not cited or len(set(cited)) != len(cited):
            continue
        if any(e not in diagnosis_ids or e not in transcript_ids for e in cited):
            continue
        safe_diagnostics.append({
            "toolName": name,
            "arguments": arguments,
            "evidence": cited,
        })

    if not safe_diagnostics:
        return JSONResponse({"error": "no valid evidence-grounded diagnostic plan"}, status_code=422)

    # A single trace context is created for this run and reused by later receipts.
    trace_context = make_trace_context(request.headers)
    run_span_id = new_id(8)
    agent_span_id = new_id(8)
    model_span_id = new_id(8)
    now = time.time_ns()
    base = span_attr_list(run_id, marker)

    spans = [
        span(
            trace_context["traceId"], run_span_id,
            trace_context["remoteParentId"], "POST /v2/incidents", 2,
            base + [attr("http.request.method", "POST"),
                    attr("http.route", "/v2/incidents")],
            now, now + 1,
        ),
        span(
            trace_context["traceId"], agent_span_id, run_span_id,
            "invoke_agent " + str(body.get("agentName", "incident-response")),
            1, base, now + 1, now + 2,
        ),
        span(
            trace_context["traceId"], model_span_id, agent_span_id,
            "chat incident-plan", 3,
            base + [
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.request.model", os.getenv("GEMINI_MODEL", "gemini-3.8-flash")),
            ],
            now + 2, now + 3,
        ),
    ]

    dispatches = []
    actions = []
    for item in safe_diagnostics:
        action_id = opaque_id()
        call_id = opaque_id()
        client_span_id = new_id(8)
        logical_span_id = new_id(8)
        dispatch = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": item["toolName"],
            "arguments": item["arguments"],
            "evidence": item["evidence"],
            "attempt": 1,
            "traceparent": (
                f"00-{trace_context['traceId']}-{client_span_id}-"
                f"{trace_context['traceFlags']}"
            ),
        }
        if trace_context.get("tracestate"):
            dispatch["tracestate"] = trace_context["tracestate"]
        dispatches.append(dispatch)
        actions.append({
            **dispatch,
            "_clientSpanId": client_span_id,
            "_logicalSpanId": logical_span_id,
            "_outcome": None,
        })

        tool_attrs = span_attr_list(run_id, marker, {
            "ga5.action.id": action_id,
            "gen_ai.tool.name": item["toolName"],
            "gen_ai.tool.call.id": call_id,
            "gen_ai.operation.name": "execute_tool",
        })
        spans.append(span(
            trace_context["traceId"], logical_span_id, agent_span_id,
            "execute_tool " + item["toolName"], 1, tool_attrs,
            now + 3, now + 4,
        ))
        spans.append(span(
            trace_context["traceId"], client_span_id, logical_span_id,
            "POST tool/" + item["toolName"], 3,
            span_attr_list(run_id, marker, {
                "ga5.action.id": action_id,
                "ga5.attempt": 1,
                "http.request.method": "POST",
                "http.request.resend_count": 0,
            }),
            now + 4, now + 5,
        ))

    if len(safe_diagnostics) > 1:
        join_id = new_id(8)
        spans.append(span(
            trace_context["traceId"], join_id, agent_span_id,
            "incident.join", 1, base, now + 5, now + 6,
            links=[{
                "traceId": trace_context["traceId"],
                "spanId": action["_logicalSpanId"],
            } for action in actions],
        ))

    state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": plan["rootCause"],
            "evidence": diagnosis_ids,
        },
        "dispatches": dispatches,
        "approvals": [],
        "otlp": build_otlp(spans),
    }

    internal = {
        "traceContext": trace_context,
        "traceSpans": spans,
        "agentSpanId": agent_span_id,
        "actions": actions,
        "diagnosis": state["diagnosis"],
        "reasoning": plan.get("reasoning", ""),
        "effectCandidates": plan.get("effectCandidates", []),
        "receiptLog": [],
        "actionLog": [],
        "pendingApproval": None,
        "chosenEffect": None,
        "suppressed": [],
        "approvalGateAdded": False,
    }

    # Persist before responding so a replay cannot create new actions.
    with database() as db:
        db.execute(
            """INSERT INTO incidents
               (run_id,request_json,state_json,internal_json)
               VALUES(?,?,?,?)""",
            (run_id, request_json, canonical(state), canonical(internal)),
        )

    return JSONResponse(state)


@app.get("/v2/incidents/{run_id}")
def get_incident(run_id: str):
    saved = load_incident(run_id)
    if not saved:
        return JSONResponse({"error": "incident not found"}, status_code=404)
    return JSONResponse(saved["state"])


def update_span_attributes(target, updates):
    """Replace attributes by key without exporting arguments or results."""
    attrs = target.setdefault("attributes", [])
    for key, value in updates.items():
        attrs[:] = [item for item in attrs if item.get("key") != key]
        attrs.append(attr(key, value))


def find_tool(request_body, name):
    for tool in request_body.get("toolCatalog", []):
        if isinstance(tool, dict) and tool.get("name") == name:
            return tool
    return None


def trace_for_state(internal):
    return internal["traceContext"]["traceId"]


def record_tool_outcome(internal, action, receipt_id, outcome):
    """Attach receipt metadata to the CLIENT span for this physical attempt."""
    trace_id = trace_for_state(internal)
    action_id = action["actionId"]
    attempt = outcome["attempt"]

    target = None
    for item in internal["traceSpans"]:
        attrs = {
            pair["key"]: pair["value"]
            for pair in item.get("attributes", [])
        }
        if (
            item.get("traceId") == trace_id
            and item.get("kind") == 3
            and item.get("name") == "POST tool/" + action["toolName"]
            and attrs.get("ga5.action.id", {}).get("stringValue") == action_id
            and attrs.get("ga5.attempt", {}).get("intValue") == str(attempt)
        ):
            target = item
            break

    if target is None:
        return

    updates = {
        "ga5.receipt.id": receipt_id,
        "ga5.receipt.nonce": outcome.get("nonce", ""),
        "http.response.status_code": outcome["status"],
        "http.request.method": "POST",
        "http.request.resend_count": attempt - 1,
    }

    error_type = outcome.get("errorType")
    status = outcome["status"]
    if status == 503:
        error_type = "503"
    if status == 0 and error_type == "timeout":
        error_type = "timeout"

    if error_type:
        updates["error.type"] = error_type
        target["status"] = {"code": 2}
    else:
        target["status"] = {"code": 0}
        target["attributes"] = [
            item for item in target.get("attributes", [])
            if item.get("key") != "error.type"
        ]

    update_span_attributes(target, updates)


def make_tool_dispatch(request_body, internal, tool_name, arguments,
                       phase, evidence, action_id=None, call_id=None,
                       attempt=1, approval_id=None, approval_nonce=None):
    trace_id = trace_for_state(internal)
    agent_id = internal["agentSpanId"]
    run_id = request_body["runId"]
    marker = request_body["publicMarker"]

    action_id = action_id or opaque_id()
    call_id = call_id or opaque_id()
    logical_span_id = new_id(8)
    client_span_id = new_id(8)

    dispatch = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": evidence,
        "attempt": attempt,
        "traceparent": (
            f"00-{trace_id}-{client_span_id}-"
            f"{internal['traceContext']['traceFlags']}"
        ),
    }
    if internal["traceContext"].get("tracestate"):
        dispatch["tracestate"] = internal["traceContext"]["tracestate"]
    if approval_id:
        dispatch["approvalId"] = approval_id
        dispatch["approvalNonce"] = approval_nonce

    base = span_attr_list(run_id, marker)
    internal["traceSpans"].append(span(
        trace_id, logical_span_id, agent_id,
        "execute_tool " + tool_name, 1,
        base + [
            attr("ga5.action.id", action_id),
            attr("gen_ai.tool.name", tool_name),
            attr("gen_ai.tool.call.id", call_id),
            attr("gen_ai.operation.name", "execute_tool"),
        ],
    ))
    internal["traceSpans"].append(span(
        trace_id, client_span_id, logical_span_id,
        "POST tool/" + tool_name, 3,
        base + [
            attr("ga5.action.id", action_id),
            attr("ga5.attempt", attempt),
            attr("http.request.method", "POST"),
            attr("http.request.resend_count", attempt - 1),
        ],
    ))

    action = {
        **dispatch,
        "_clientSpanId": client_span_id,
        "_logicalSpanId": logical_span_id,
        "_outcome": None,
    }
    internal["actions"].append(action)
    internal["actionLog"].append(dispatch.copy())
    return dispatch


def update_public_state(state, internal, dispatches, approvals):
    state["dispatches"] = dispatches
    state["approvals"] = approvals
    state["otlp"] = build_otlp(internal["traceSpans"])
    state["status"] = "waiting"
    state.pop("chosenEffect", None)
    state.pop("suppressed", None)
    state.pop("actionLog", None)
    state.pop("receiptLog", None)
    return state


def finish_incident(state, internal, status):
    state["status"] = status
    state.pop("dispatches", None)
    state.pop("approvals", None)
    state["chosenEffect"] = internal.get("chosenEffect")
    state["suppressed"] = internal.get("suppressed", [])
    state["actionLog"] = internal["actionLog"]
    state["receiptLog"] = internal["receiptLog"]
    state["otlp"] = build_otlp(internal["traceSpans"])
    return state


def choose_effect(request_body, internal):
    policy = request_body["policy"]
    permitted = policy.get("effectTools", [])
    candidates = internal.get("effectCandidates", [])

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        name = candidate.get("toolName")
        arguments = candidate.get("arguments")
        evidence = candidate.get("evidenceIds")
        if (
            name in permitted
            and find_tool(request_body, name)
            and isinstance(arguments, dict)
            and isinstance(evidence, list)
            and evidence
            and all(e in internal["diagnosis"]["evidence"] for e in evidence)
        ):
            return candidate
    return None


def add_approval_gate(request_body, internal, approval, receipt_nonce=None):
    if not internal.get("approvalGateAdded"):
        internal["traceSpans"].append(span(
            trace_for_state(internal),
            new_id(8),
            internal["agentSpanId"],
            "approval_gate",
            1,
            span_attr_list(
                request_body["runId"],
                request_body["publicMarker"],
                {
                    "ga5.approval.id": approval["approvalId"],
                    "ga5.approval.nonce": receipt_nonce or "",
                },
            ),
        ))
        internal["approvalGateAdded"] = True
    else:
        for item in internal["traceSpans"]:
            if item.get("name") == "approval_gate":
                update_span_attributes(item, {
                    "ga5.approval.id": approval["approvalId"],
                    "ga5.approval.nonce": receipt_nonce or "",
                })


def advance_after_diagnostics(request_body, state, internal):
    diagnostic_actions = [
        action for action in internal["actions"]
        if action["phase"] == "diagnostic"
    ]
    if any(action["_outcome"] is None for action in diagnostic_actions):
        return update_public_state(state, internal, [], [])

    failures = [
        action for action in diagnostic_actions
        if not action["_outcome"].get("success")
    ]
    if failures:
        internal["suppressed"].append({
            "reason": "diagnostic_failed",
            "actionIds": [action["actionId"] for action in failures],
        })
        return finish_incident(state, internal, "failed")

    # A reported scaling/capacity limit means do not attempt another scale.
    limit_seen = any(
        word in str(action["_outcome"].get("resultClass", "")).lower()
        for action in diagnostic_actions
        for word in ("scaling_limit", "capacity_limit", "at_limit")
    )
    candidate = choose_effect(request_body, internal)

    if limit_seen:
        candidates = internal.get("effectCandidates", [])
        page = next(
            (
                item for item in candidates
                if isinstance(item, dict)
                and isinstance(item.get("toolName"), str)
                and item.get("toolName") in request_body["policy"].get("effectTools", [])
                and find_tool(request_body, item.get("toolName"))
                and any(
                    word in (
                        item["toolName"] + " "
                        + str(find_tool(request_body, item["toolName"]).get("description", ""))
                    ).lower()
                    for word in ("page", "notify", "alert", "owner", "on_call", "oncall", "pager")
                )
                and "scale" not in item["toolName"].lower()
            ),
            None,
        )
        candidate = page
        if candidate is None:
            internal["suppressed"].append({
                "reason": "scaling_limit_reached",
                "effect": "scale_service",
            })

    if not candidate:
        if not internal["suppressed"]:
            internal["suppressed"].append({
                "reason": "no_justified_permitted_effect",
            })
        return finish_incident(state, internal, "failed")

    name = candidate["toolName"]
    args = candidate["arguments"]
    action_id = opaque_id()
    internal["chosenEffect"] = name

    if name in set(request_body["policy"].get("approvalRequiredFor", [])) \
            or name in DESTRUCTIVE_TOOLS:
        approval = {
            "approvalId": opaque_id(),
            "actionId": action_id,
            "toolName": name,
            "argumentsDigest": digest(args),
        }
        internal["pendingApproval"] = {
            **approval,
            "arguments": args,
            "evidence": candidate["evidenceIds"],
        }
        add_approval_gate(request_body, internal, approval)
        state["dispatches"] = []
        state["approvals"] = [approval]
        state["otlp"] = build_otlp(internal["traceSpans"])
        state["status"] = "waiting"
        return state

    dispatch = make_tool_dispatch(
        request_body, internal, name, args, "effect",
        candidate["evidenceIds"], action_id=action_id,
    )
    state["dispatches"] = [dispatch]
    state["approvals"] = []
    state["otlp"] = build_otlp(internal["traceSpans"])
    state["status"] = "waiting"
    return state


@app.post("/v2/incidents/{run_id}/receipts")
async def receive_receipt(run_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "receipt must be an object"}, status_code=400)

    receipt_id = body.get("receiptId")
    if not isinstance(receipt_id, str) or len(receipt_id) < 8:
        return JSONResponse({"error": "invalid receiptId"}, status_code=422)

    receipt_json = canonical(body)
    with database() as db:
        prior_receipt = db.execute(
            "SELECT run_id,receipt_json,response_json FROM receipts WHERE receipt_id=?",
            (receipt_id,),
        ).fetchone()

    if prior_receipt:
        if (
            prior_receipt["run_id"] != run_id
            or prior_receipt["receipt_json"] != receipt_json
        ):
            return JSONResponse({"error": "receiptId conflict"}, status_code=409)
        return JSONResponse(json.loads(prior_receipt["response_json"]))

    saved = load_incident(run_id)
    if not saved:
        return JSONResponse({"error": "incident not found"}, status_code=404)

    state = saved["state"]
    internal = saved["internal"]
    request_body = saved["request"]

    outcomes = body.get("outcomes")
    approvals = body.get("approvals")
    has_outcomes = isinstance(outcomes, list)
    has_approvals = isinstance(approvals, list)
    if has_outcomes == has_approvals:
        return JSONResponse(
            {"error": "provide exactly one of outcomes or approvals"},
            status_code=422,
        )

    if state["status"] != "waiting":
        return JSONResponse({"error": "incident has no pending work"}, status_code=422)

    new_dispatches = []
    new_approvals = []

    if has_outcomes:
        if not outcomes:
            return JSONResponse({"error": "outcomes cannot be empty"}, status_code=422)

        # Validate every outcome before changing any state.
        matched = []
        for outcome in outcomes:
            if not isinstance(outcome, dict):
                return JSONResponse({"error": "invalid outcome"}, status_code=422)
            required = ("actionId", "callId", "attempt", "status", "resultClass", "nonce")
            if any(key not in outcome for key in required):
                return JSONResponse({"error": "incomplete outcome"}, status_code=422)

            action = next((
                item for item in internal["actions"]
                if item["actionId"] == outcome["actionId"]
                and item["callId"] == outcome["callId"]
                and item["attempt"] == outcome["attempt"]
                and item["_outcome"] is None
            ), None)
            if action is None:
                return JSONResponse({"error": "outcome is not for a pending call"}, status_code=422)
            if not isinstance(outcome["status"], int) or isinstance(outcome["status"], bool):
                return JSONResponse({"error": "invalid outcome status"}, status_code=422)
            if not isinstance(outcome["nonce"], str) or not outcome["nonce"]:
                return JSONResponse({"error": "invalid outcome nonce"}, status_code=422)
            matched.append((action, outcome))

        # Ensure the same logical action is not supplied twice in one receipt.
        if len({(o["actionId"], o["attempt"]) for _, o in matched}) != len(matched):
            return JSONResponse({"error": "duplicate outcome"}, status_code=422)

        # Record the first dispatches exactly as issued.
        if not internal["actionLog"]:
            internal["actionLog"] = [
                item.copy() for item in state.get("dispatches", [])
            ]

        # Remove only dispatch attempts acknowledged by this receipt.
        # Other parallel calls must remain pending.
        processed_keys = {
            (o["actionId"], o["callId"], o["attempt"])
            for _, o in matched
        }

        for action, outcome in matched:
            status_code = outcome["status"]
            error_type = outcome.get("errorType")
            if status_code == 0 and error_type != "timeout":
                return JSONResponse({"error": "status 0 requires timeout errorType"}, status_code=422)

            record_tool_outcome(internal, action, receipt_id, outcome)
            log_entry = {
                "receiptId": receipt_id,
                "actionId": action["actionId"],
                "callId": action["callId"],
                "attempt": outcome["attempt"],
                "status": status_code,
                "resultClass": outcome["resultClass"],
                "nonce": outcome["nonce"],
            }
            if error_type:
                log_entry["errorType"] = error_type
            internal["receiptLog"].append(log_entry)

            if status_code == 503 and action["attempt"] == 1:
                action["attempt"] = 2
                client_span_id = new_id(8)
                action["_clientSpanId"] = client_span_id
                trace_id = trace_for_state(internal)
                dispatch = {
                    key: action[key]
                    for key in (
                        "actionId", "callId", "phase", "toolName",
                        "arguments", "evidence", "attempt",
                    )
                }
                dispatch["traceparent"] = (
                    f"00-{trace_id}-{client_span_id}-"
                    f"{internal['traceContext']['traceFlags']}"
                )
                if internal["traceContext"].get("tracestate"):
                    dispatch["tracestate"] = internal["traceContext"]["tracestate"]
                if action.get("approvalId"):
                    dispatch["approvalId"] = action["approvalId"]
                    dispatch["approvalNonce"] = action["approvalNonce"]

                internal["traceSpans"].append(span(
                    trace_id, client_span_id, action["_logicalSpanId"],
                    "POST tool/" + action["toolName"], 3,
                    span_attr_list(
                        run_id, request_body["publicMarker"], {
                            "ga5.action.id": action["actionId"],
                            "ga5.attempt": 2,
                            "http.request.method": "POST",
                            "http.request.resend_count": 1,
                        }
                    ),
                ))
                internal["actionLog"].append(dispatch.copy())
                new_dispatches.append(dispatch)
                continue

            success = 200 <= status_code < 300
            if status_code == 0 and error_type == "timeout":
                success = False
            action["_outcome"] = {
                "success": success,
                "status": status_code,
                "resultClass": outcome["resultClass"],
                "errorType": error_type,
            }

        # Preserve unacknowledged dispatches and add any retries.
        pending_dispatches = [
            dispatch
            for dispatch in state.get("dispatches", [])
            if (
                dispatch["actionId"],
                dispatch["callId"],
                dispatch["attempt"],
            ) not in processed_keys
        ]
        pending_dispatches.extend(new_dispatches)

        if pending_dispatches:
            state["dispatches"] = pending_dispatches
            state["approvals"] = []
            state["otlp"] = build_otlp(internal["traceSpans"])
            state["status"] = "waiting"
        elif any(
            action["phase"] == "diagnostic" and action["_outcome"] is None
            for action in internal["actions"]
        ):
            state["dispatches"] = []
            state["approvals"] = []
            state["otlp"] = build_otlp(internal["traceSpans"])
            state["status"] = "waiting"
        elif any(
            action["phase"] == "diagnostic"
            for action in internal["actions"]
        ) and not any(
            action["phase"] == "effect"
            for action in internal["actions"]
        ):
            state = advance_after_diagnostics(request_body, state, internal)
        else:
            effect_actions = [
                action for action in internal["actions"]
                if action["phase"] == "effect"
            ]
            if effect_actions and all(a["_outcome"] is not None for a in effect_actions):
                final_status = (
                    "completed"
                    if all(a["_outcome"]["success"] for a in effect_actions)
                    else "failed"
                )
                state = finish_incident(state, internal, final_status)
            else:
                state["dispatches"] = []
                state["approvals"] = []
                state["otlp"] = build_otlp(internal["traceSpans"])

    else:
        if not approvals or len(approvals) != 1:
            return JSONResponse({"error": "expected one approval decision"}, status_code=422)
        pending = internal.get("pendingApproval")
        approval_receipt = approvals[0]
        if not pending or not isinstance(approval_receipt, dict):
            return JSONResponse({"error": "no pending approval"}, status_code=422)
        if approval_receipt.get("approvalId") != pending["approvalId"]:
            return JSONResponse({"error": "approval ID mismatch"}, status_code=422)
        if approval_receipt.get("decision") not in ("approved", "rejected"):
            return JSONResponse({"error": "invalid approval decision"}, status_code=422)
        nonce = approval_receipt.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return JSONResponse({"error": "invalid approval nonce"}, status_code=422)

        internal["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": pending["approvalId"],
            "decision": approval_receipt["decision"],
            "nonce": nonce,
        })
        add_approval_gate(request_body, internal, pending, nonce)
        internal["pendingApproval"] = None

        if approval_receipt["decision"] != "approved":
            internal["suppressed"].append({
                "reason": "approval_rejected",
                "actionId": pending["actionId"],
            })
            state = finish_incident(state, internal, "failed")
        else:
            dispatch = make_tool_dispatch(
                request_body, internal,
                pending["toolName"], pending["arguments"],
                "effect", pending["evidence"],
                action_id=pending["actionId"],
                approval_id=pending["approvalId"],
                approval_nonce=nonce,
            )
            new_dispatches.append(dispatch)
            state["dispatches"] = new_dispatches
            state["approvals"] = []
            state["otlp"] = build_otlp(internal["traceSpans"])
            state["status"] = "waiting"

    # Store the updated incident and exact receipt response before replying.
    store_state(run_id, state, internal)
    with database() as db:
        db.execute(
            """INSERT INTO receipts(receipt_id,run_id,receipt_json,response_json)
               VALUES(?,?,?,?)""",
            (receipt_id, run_id, receipt_json, canonical(state)),
        )

    return JSONResponse(state)
