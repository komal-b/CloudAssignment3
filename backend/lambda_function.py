import json
import os
import uuid
import urllib.parse

import boto3
import urllib3
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.session import Session

# === Clients ===
lex = boto3.client("lexv2-runtime")
http = urllib3.PoolManager()

REGION = os.environ.get("AWS_REGION", "us-east-1")
OPENSEARCH_ENDPOINT = os.environ["OPENSEARCH_ENDPOINT"]  # https://...aos.us-east-1.on.aws
INDEX = os.environ.get("INDEX", "photos")

LEX_BOT_ID = os.environ["LEX_BOT_ID"]
LEX_BOT_ALIAS_ID = os.environ["LEX_BOT_ALIAS_ID"]
LEX_LOCALE_ID = os.environ.get("LEX_LOCALE_ID", "en_US")


# ---------- Helpers ----------

def sign_and_send(method: str, url: str, body: str | None = None, headers: dict | None = None):
    """
    SigV4 sign and send an HTTP request to OpenSearch.
    Same idea as in index-photos Lambda.
    """
    headers = headers or {}
    if body is not None:
        headers["Content-Type"] = "application/json"

    creds = Session().get_credentials()
    req = AWSRequest(method=method, url=url, data=body, headers=headers)
    SigV4Auth(creds, "es", REGION).add_auth(req)

    resp = http.request(
        method=method,
        url=url,
        body=body,
        headers=dict(req.headers),
        retries=False,
        timeout=urllib3.Timeout(connect=3.0, read=10.0),
    )
    return resp.status, resp.data.decode("utf-8", errors="replace")


def extract_query(event) -> str:
    """
    Get the natural-language query 'q' from different event shapes.
    - API Gateway HTTP/REST: event['queryStringParameters']['q']
    - Direct test: event['q']
    """
    # API Gateway (HTTP or REST)
    q = None
    if isinstance(event, dict):
        qsp = event.get("queryStringParameters") or {}
        if isinstance(qsp, dict) and "q" in qsp:
            q = qsp.get("q")

        # direct test events
        if not q:
            q = event.get("q")

    if not q:
        return ""
    return str(q).strip()


def call_lex_for_keywords(text: str) -> list[str]:
    """
    Send the user query to Lex and extract KeywordOne / KeywordTwo slots.
    """
    if not text:
        return []

    session_id = "sess-" + uuid.uuid4().hex[:8]

    resp = lex.recognize_text(
        botId=LEX_BOT_ID,
        botAliasId=LEX_BOT_ALIAS_ID,
        localeId=LEX_LOCALE_ID,
        sessionId=session_id,
        text=text,
    )

    intent = (resp.get("sessionState") or {}).get("intent") or {}
    slots = intent.get("slots") or {}

    def slot_value(slot_obj):
        if not slot_obj:
            return None
        value = slot_obj.get("value") or {}
        # interpretedValue (Lex V2) is usually what we want
        return (value.get("interpretedValue")
                or value.get("originalValue"))

    kw1 = slot_value(slots.get("KeywordOne"))
    kw2 = slot_value(slots.get("KeywordTwo"))

    keywords = []
    for kw in (kw1, kw2):
        if kw:
            keywords.append(kw.lower().strip())

    print("LEX INTENT:", json.dumps(intent))
    print("LEX KEYWORDS:", keywords)

    return keywords


def search_opensearch(keywords: list[str]) -> list[dict]:
    """
    Search the 'photos' index by labels.
    Returns a list of result objects with objectKey, bucket, url, labels, createdTimestamp.
    """
    if not keywords:
        return []

    # Simple bool/should query so any of the labels can match.
    # We use `match` instead of `terms` so it's a bit more forgiving.
    should_clauses = [{"match": {"labels": kw}} for kw in keywords]

    query = {
        "size": 50,
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        }
    }

    url = f"{OPENSEARCH_ENDPOINT.rstrip('/')}/{INDEX}/_search"

    # IMPORTANT CHANGE: POST with JSON body, not GET with ?source=...
    status, data = sign_and_send("POST", url, body=json.dumps(query))

    print("OS_SEARCH_STATUS:", status)
    print("OS_SEARCH_RAW:", data[:500])  # truncate in logs

    if status < 200 or status >= 300:
        # On error, just return empty results
        return []

    body = json.loads(data)
    hits = (body.get("hits") or {}).get("hits") or []

    results = []
    for h in hits:
        src = h.get("_source") or {}
        bucket = src.get("bucket")
        key = src.get("objectKey")
        if not bucket or not key:
            continue

        url = f"https://{bucket}.s3.amazonaws.com/{urllib.parse.quote(key)}"

        results.append({
            "objectKey": key,
            "bucket": bucket,
            "createdTimestamp": src.get("createdTimestamp"),
            "labels": src.get("labels", []),
            "url": url,
        })

    return results



def make_response(status_code: int, body_obj: dict):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET,OPTIONS",
        },
        "body": json.dumps(body_obj),
    }


# ---------- Lambda entry ----------

def lambda_handler(event, context):
    print("EVENT:", json.dumps(event))

    q = extract_query(event)
    print("QUERY:", q)

    if not q:
        return make_response(200, {"results": []})

    # 1) Disambiguate with Lex -> get keywords
    keywords = call_lex_for_keywords(q)

    # 2) If no keywords, return empty per spec
    if not keywords:
        return make_response(200, {"results": []})

    # 3) Search OpenSearch for matching photos
    results = search_opensearch(keywords)

    return make_response(200, {"results": results})
