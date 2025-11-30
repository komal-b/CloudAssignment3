import json
import os
import urllib.parse
from datetime import timezone

import boto3
import urllib3
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.session import Session

# AWS clients
s3 = boto3.client("s3")
rekognition = boto3.client("rekognition")
http = urllib3.PoolManager()

REGION = os.environ.get("AWS_REGION", "us-east-1")
OPENSEARCH_ENDPOINT = os.environ["OPENSEARCH_ENDPOINT"]  # e.g. https://search-xxxx.us-east-1.es.amazonaws.com
INDEX = os.environ.get("INDEX", "photos")
MAX_LABELS = int(os.environ.get("MAX_LABELS", "10"))
MIN_CONFIDENCE = float(os.environ.get("MIN_CONFIDENCE", "70"))


def sign_and_send(method: str, url: str, body: str | None = None, headers: dict | None = None):
    """SigV4 sign and send an HTTP request to OpenSearch."""
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


def normalize_custom_labels(meta: dict) -> list[str]:
    """
    S3 user metadata keys are lowercased by AWS in head_object() response.
    Accept both x-amz-meta-customLabels and x-amz-meta-custom_labels styles.
    """
    raw = meta.get("customlabels") or meta.get("custom_labels") or ""
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def is_supported_image_content_type(content_type: str | None) -> bool:
    # Rekognition DetectLabels supports common image formats (jpeg/png are safest).
    # WebP often fails depending on how it was produced.
    if not content_type:
        return True  # don't block; let Rekognition decide
    content_type = content_type.lower()
    return content_type in ("image/jpeg", "image/jpg", "image/png")


def lambda_handler(event, context):
    print("EVENT:", json.dumps(event))
    print("OPENSEARCH_ENDPOINT:", OPENSEARCH_ENDPOINT)
    print("INDEX URL example:", f"{OPENSEARCH_ENDPOINT.rstrip('/')}/{INDEX}/_doc")


    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        if not event_name.startswith("ObjectCreated:"):
            # This Lambda is meant for PUT uploads; skip other event types.
            print(f"Skipping unsupported eventName={event_name}")
            continue

        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        event_time = record.get("eventTime")  # ISO string

        # 1) HeadObject: metadata + LastModified + ContentType
        head = s3.head_object(Bucket=bucket, Key=key)
        meta = head.get("Metadata", {})
        last_modified = head["LastModified"].astimezone(timezone.utc).isoformat()
        content_type = head.get("ContentType")

        custom_labels = normalize_custom_labels(meta)

        # 2) Rekognition DetectLabels
        rek_labels = []
        if is_supported_image_content_type(content_type):
            try:
                rek = rekognition.detect_labels(
                    Image={"S3Object": {"Bucket": bucket, "Name": key}},
                    MaxLabels=MAX_LABELS,
                    MinConfidence=MIN_CONFIDENCE,
                )
                rek_labels = [lbl["Name"].lower() for lbl in rek.get("Labels", [])]
            except rekognition.exceptions.InvalidImageFormatException as e:
                print(f"[WARN] Rekognition InvalidImageFormat for {bucket}/{key}: {str(e)}")
            except Exception as e:
                print(f"[ERROR] Rekognition failed for {bucket}/{key}: {str(e)}")
                raise
        else:
            print(f"[WARN] Skipping Rekognition due to unsupported ContentType={content_type} for {bucket}/{key}")

        labels = sorted(set(rek_labels + custom_labels))

        # 3) Build doc
        doc = {
            "objectKey": key,
            "bucket": bucket,
            "createdTimestamp": event_time or last_modified,
            "labels": labels,
        }

        print("DOC:", json.dumps(doc))

        # 4) Index into OpenSearch: POST /photos/_doc
        url = f"{OPENSEARCH_ENDPOINT.rstrip('/')}/{INDEX}/_doc"
        status, data = sign_and_send("POST", url, body=json.dumps(doc))

        # 5) Log indexing proof
        print("OPENSEARCH_STATUS:", status)
        print("OPENSEARCH_RESPONSE:", data)

        # Optional: fail the Lambda if indexing failed, so you notice it immediately
        if status < 200 or status >= 300:
            raise RuntimeError(f"OpenSearch indexing failed: HTTP {status} body={data}")

    return {"statusCode": 200, "body": "ok"}
