# Install necessary Google Cloud SDK libraries for Colab environment
%pip install --quiet google-cloud-dlp google-cloud-storage

#!/usr/bin/env python3
"""
Securing Data Used for AI Applications — automated PII sanitization pipeline.

Builds the same resources as the Google Codelab, but in code, using the
Sensitive Data Protection (Cloud DLP) API:

  1. Inspect template          pii-finder                 (what counts as sensitive)
  2. De-identify templates     de-identify-unstructured   (text/logs -> [INFO_TYPE])
                               de-identify-structured     (CSV user_id/message -> masked with #)
                               de-identify-image          (redaction boxes over PII in images)
  3. Inspection job            pii-remover                (scans gs://input-<project>, writes
                                                           de-identified copies to gs://output-<project>)
  4. Verification              before/after comparison of input vs. output files

Usage (run in Cloud Shell after ./setup.sh):
  python3 dlp_pipeline.py templates     # create / replace the 4 templates
  python3 dlp_pipeline.py test          # quick API sanity test on a sample string
  python3 dlp_pipeline.py job           # create the pii-remover job
  python3 dlp_pipeline.py wait          # poll the job until DONE, print findings
  python3 dlp_pipeline.py verify        # print before/after for text + CSV, list images
  python3 dlp_pipeline.py all           # templates -> test -> job -> wait -> verify
  python3 dlp_pipeline.py cleanup       # delete job + templates (buckets: see cleanup.sh)

Project is taken from --project, $GOOGLE_CLOUD_PROJECT, or `gcloud config`.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from google.api_core import exceptions as gexc
from google.cloud import dlp_v2, storage

LOCATION = "global"

INSPECT_TEMPLATE_ID = "pii-finder"
UNSTRUCTURED_TEMPLATE_ID = "de-identify-unstructured"
STRUCTURED_TEMPLATE_ID = "de-identify-structured"
IMAGE_TEMPLATE_ID = "de-identify-image"
JOB_ID = "pii-remover"

# infoTypes from the codelab's inspect template.
INFO_TYPES = [
    "CREDIT_CARD_EXPIRATION_DATE",
    "CREDIT_CARD_NUMBER",
    "DATE_OF_BIRTH",
    "DRIVERS_LICENSE_NUMBER",
    "EMAIL_ADDRESS",
    "GCP_API_KEY",
    "GCP_CREDENTIALS",
    "ORGANIZATION_NAME",
    "PASSWORD",
    "PERSON_NAME",
    "PHONE_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
 ]

# CSV columns to sanitize. agent_id (employee address) is intentionally left alone.
STRUCTURED_FIELDS = ["user_id", "message"]

TEST_STRING = (
    "Hi, my name is Alex and my SSN is 555-11-5555. "
    "You can reach me at +1-555-555-5555."
)


