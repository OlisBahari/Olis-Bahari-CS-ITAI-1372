# Filemame......: dlp_pipeline.py
# Language......: Python
# Tools.......... Visual Source Code (VSC)
# Class.........: ITAI 1372 Artificial Intelligence in Cybersecurity
# Semster.......: Fall 2026
# Class Type....: Online
# Instructor....: Hien Nguyen
# Student.......: Olis Bahari
# Version.......: V1.0

"""Google Cloud Sensitive Data Protection (DLP) lab pipeline.

Python 3.10+. Install: pip install google-cloud-dlp google-cloud-storage
Authenticate: gcloud auth application-default login
Set project: set GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID  (Windows cmd)

Examples:
  python dlp_pipeline.py templates
  python dlp_pipeline.py test
  python dlp_pipeline.py verify --samples "Contact jane@example.com" "Call 415-555-0199"
  python dlp_pipeline.py job --bucket YOUR_BUCKET
"""
import argparse
import os
import sys
from google.api_core.exceptions import AlreadyExists, GoogleAPICallError
from google.cloud import dlp_v2

LOCATION = "global"
INSPECT_ID = "pii-finder"
DEIDENTIFY_ID = "de-identify-unstructured"
INFO_TYPES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON_NAME", "CREDIT_CARD_NUMBER", "US_SOCIAL_SECURITY_NUMBER"]
TEST_STRING = "Jane Smith can be reached at jane.smith@example.com or 415-555-0199."


def parent(project):
    return f"projects/{project}/locations/{LOCATION}"


def inspect_name(project):
    return f"{parent(project)}/inspectTemplates/{INSPECT_ID}"


def deidentify_name(project):
    return f"{parent(project)}/deidentifyTemplates/{DEIDENTIFY_ID}"


def cmd_templates(dlp, project):
    p = parent(project)
    inspect_config = {
        "info_types": [{"name": t} for t in INFO_TYPES],
        "min_likelihood": dlp_v2.Likelihood.POSSIBLE,
    }
    deidentify_config = {
        "info_type_transformations": {
            "transformations": [{
                "primitive_transformation": {
                    "replace_config": {"new_value": {"string_value": "[REDACTED]"}}
                }
            }]
        }
    }
    try:
        dlp.create_inspect_template(request={
            "parent": p, "template_id": INSPECT_ID,
            "inspect_template": {"display_name": "PII Finder", "inspect_config": inspect_config}
        })
        print("Created:", inspect_name(project))
    except AlreadyExists:
        dlp.update_inspect_template(request={
            "name": inspect_name(project), "inspect_template": {"inspect_config": inspect_config},
            "update_mask": {"paths": ["inspect_config"]}
        })
        print("Updated:", inspect_name(project))
    try:
        dlp.create_deidentify_template(request={
            "parent": p, "template_id": DEIDENTIFY_ID,
            "deidentify_template": {"display_name": "De-identify Unstructured", "deidentify_config": deidentify_config}
        })
        print("Created:", deidentify_name(project))
    except AlreadyExists:
        dlp.update_deidentify_template(request={
            "name": deidentify_name(project), "deidentify_template": {"deidentify_config": deidentify_config},
            "update_mask": {"paths": ["deidentify_config"]}
        })
        print("Updated:", deidentify_name(project))


def deidentify(dlp, project, value):
    return dlp.deidentify_content(request={
        "parent": parent(project),
        "inspect_template_name": inspect_name(project),
        "deidentify_template_name": deidentify_name(project),
        "item": {"value": value},
    }).item.value


def cmd_test(dlp, project):
    print("Input:", TEST_STRING)
    print("Output:", deidentify(dlp, project, TEST_STRING))


def cmd_verify(dlp, project, samples):
    for index, sample in enumerate(samples, 1):
        print(f"Sample {index}:")
        print("  Input: ", sample)
        print("  Output:", deidentify(dlp, project, sample))


def cmd_job(dlp, project, bucket):
    if not bucket:
        raise ValueError("--bucket is required for the job command")
    bucket = bucket.removeprefix("gs://").strip("/")
    if "/" in bucket or not bucket:
        raise ValueError("Provide a bucket name only, e.g. --bucket my-bucket")
    job = dlp.create_dlp_job(request={
        "parent": parent(project),
        "job": {
            "inspect_job": {
                "inspect_template_name": inspect_name(project),
                "storage_config": {
                    "cloud_storage_options": {
                        "file_set": {"url": f"gs://{bucket}/*"},
                        "bytes_limit_per_file": 1048576,
                    }
                },
            }
        },
    })
    print("Created inspection job:", job.name)
    print("This job scans Cloud Storage; it does not modify or de-identify bucket files.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Google Cloud DLP PII lab")
    parser.add_argument("command", choices=["templates", "test", "job", "verify"])
    parser.add_argument("--project", default=os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT"))
    parser.add_argument("--bucket", help="Cloud Storage bucket for job")
    parser.add_argument("--samples", nargs="+", default=[TEST_STRING], help="Text samples for verify")
    args = parser.parse_args(argv)
    if not args.project:
        parser.error("Set GOOGLE_CLOUD_PROJECT or pass --project YOUR_PROJECT_ID")
    dlp = dlp_v2.DlpServiceClient()
    try:
        if args.command == "templates":
            cmd_templates(dlp, args.project)
        elif args.command == "test":
            cmd_test(dlp, args.project)
        elif args.command == "job":
            cmd_job(dlp, args.project, args.bucket)
        elif args.command == "verify":
            cmd_verify(dlp, args.project, args.samples)
    except GoogleAPICallError as exc:
        print(f"Google Cloud API error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
