"""
Seeds Weaviate with NimbleTech.ai corporate documents.
These become the target for embedding inversion attacks.
"""
import os, time, json, requests
from sentence_transformers import SentenceTransformer
WEAVIATE = os.environ.get("WEAVIATE_URL", "http://weaviate-db:8080")
# Wait for Weaviate
for i in range(60):
    try:
        r = requests.get(f"{WEAVIATE}/v1/.well-known/ready", timeout=2)
        if r.status_code == 200:
            print("Weaviate is ready")
            break
    except Exception:
        pass
    print(f"Waiting for Weaviate... {i}")
    time.sleep(2)
# Sensitive NimbleTech corporate documents
DOCUMENTS = [
    {
        "chunk_id": "PWD-RESET-001",
        "category": "credential_reset",
        "text": "Please navigate to https://login.nimbletech.ai and reset your password. Default password is N0=Acc3ss for first-time users. Change immediately after first login."
    },
    {
        "chunk_id": "API-KEY-001",
        "category": "api_credential",
        "text": "Production OpenAI API key for the analytics pipeline: sk-nimble-prod-2026-jF4kZmP2vL5nQ8. Rotate quarterly per security policy."
    },
    {
        "chunk_id": "AWS-CRED-001",
        "category": "cloud_credential",
        "text": "AWS production access key AKIA3NIMBLE2026PROD01 with secret wJalrXUtnNIMBLE/K7MDENG/bPxR26Prod. Used by deployment role."
    },
    {
        "chunk_id": "VPN-CFG-001",
        "category": "network_config",
        "text": "GlobalProtect VPN endpoint vpn.nimbletech.ai. Pre-shared key NimbleVPN2026!Secure. MFA via Duo required for all users."
    },
    {
        "chunk_id": "JIRA-SVC-001",
        "category": "service_account",
        "text": "JIRA service account credentials. Instance jira.nimbletech.ai username jira_svc_automation password Xk9#mP2$vL5nQ8wR!jF4 for CI/CD integration."
    },
    {
        "chunk_id": "STRIPE-001",
        "category": "payment_credential",
        "text": "Stripe live secret key sk_live_nimble2026_xK9mP2vL5nQ8wR used by the billing microservice. Do not commit to git."
    },
    {
        "chunk_id": "GITHUB-PAT-001",
        "category": "vcs_credential",
        "text": "GitHub personal access token ghp_NimbleX9mP2vL5nQ8wRjF4kZ with repo and workflow scopes. Belongs to deployment bot."
    },
    {
        "chunk_id": "DB-CONN-001",
        "category": "database_credential",
        "text": "PostgreSQL production connection string postgresql://app_user:Nimble_DB_2026!@db.nimbletech.ai:5432/nimbletech_internal. Read-write access."
    },
    {
        "chunk_id": "SENDGRID-001",
        "category": "email_credential",
        "text": "SendGrid API key SG.nimble2026.xK9mP2vL5nQ8wR_jF4kZ for transactional email service. Rate limit 100 emails per second."
    },
    {
        "chunk_id": "MINIO-001",
        "category": "storage_credential",
        "text": "MinIO object storage endpoint minio.nimbletech.ai access key AKIA3NIMBLE2026DOCS secret key wJalrXUtn3NIMBLE/K7MDENG/bPxR26DocStore buckets nimble-documents nimble-archive-2025."
    },
    {
        "chunk_id": "HR-PTO-001",
        "category": "hr_policy",
        "text": "Paid Time Off Policy 2026. Employees accrue 15 days PTO per year for years 0 to 2, 20 days for years 3 to 5, and 25 days for years 6 plus. Submit requests via Workday at least 2 weeks in advance."
    },
    {
        "chunk_id": "HR-SALARY-001",
        "category": "hr_compensation",
        "text": "Compensation bands 2026. L3 engineer 120k to 150k, L4 senior 150k to 190k, L5 staff 190k to 240k, L6 principal 240k to 310k. Annual review in Q1."
    },
    {
        "chunk_id": "MEETING-Q1-001",
        "category": "meeting_notes",
        "text": "Q1 2026 board meeting summary. Revenue 47.2M up 23 percent year over year. Product roadmap approved. New office Bangalore Q3."
    },
    {
        "chunk_id": "ONBOARD-001",
        "category": "onboarding",
        "text": "New employee onboarding day one. Pick up laptop from IT desk floor 4. Default Wi-Fi password NimbleGuest2026. Connect to AD using temporary credentials provided in welcome email."
    },
    {
        "chunk_id": "SEC-AUDIT-001",
        "category": "security_audit",
        "text": "Q1 2026 security audit findings critical. Unpatched Apache Struts on prod-web-03. Default Jenkins credentials admin admin. Public S3 bucket nimble-archive-2025. No MFA on AWS root account. Hardcoded API keys in config files."
    },
    {
        "chunk_id": "ENCRYPT-001",
        "category": "encryption_key",
        "text": "Application encryption master key NimbleAES256MasterKey2026XyZ used by all services for at-rest encryption. Stored in HSM and Vault."
    },
    {
        "chunk_id": "OAUTH-001",
        "category": "oauth_credential",
        "text": "Okta SSO client secret nimble_okta_client_2026_J4kZmP2vL5nQ8wR for the internal portal integration. Redirect URI https://portal.nimbletech.ai/callback."
    },
    {
        "chunk_id": "CERT-001",
        "category": "tls_certificate",
        "text": "Wildcard TLS certificate for star.nimbletech.ai expires 2027 March 15. Private key passphrase NimbleCertPass2026!. Stored in certificate vault."
    },
    {
        "chunk_id": "CICD-001",
        "category": "ci_cd_credential",
        "text": "Jenkins deployment token jenkins_nimble_deploy_2026_kZmP2vL5 used by GitOps pipeline. Permits production deploys to all clusters."
    },
    {
        "chunk_id": "ROOT-MFA-001",
        "category": "recovery_credential",
        "text": "AWS root account recovery MFA backup codes 8472-9281-3756 1029-3847-5621 7563-1928-4750. Store in physical safe."
    },
]
# Create schema
schema = {
    "class": "DocChunk",
    "vectorizer": "none",
    "properties": [
        {"name": "chunk_id", "dataType": ["string"]},
        {"name": "category", "dataType": ["string"]},
        {"name": "text", "dataType": ["text"]},
    ]
}
# Delete existing class if present
requests.delete(f"{WEAVIATE}/v1/schema/DocChunk")
r = requests.post(f"{WEAVIATE}/v1/schema", json=schema)
print(f"Schema create: {r.status_code}")
# Load embedding model
print("Loading embedding model all-MiniLM-L6-v2 (384 dims)...")
model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
# Embed and insert
for doc in DOCUMENTS:
    emb = model.encode(doc["text"]).tolist()
    obj = {
        "class": "DocChunk",
        "properties": {
            "chunk_id": doc["chunk_id"],
            "category": doc["category"],
            "text": doc["text"]
        },
        "vector": emb
    }
    r = requests.post(f"{WEAVIATE}/v1/objects", json=obj)
    print(f"Inserted {doc['chunk_id']}: {r.status_code}")
print(f"\nTotal {len(DOCUMENTS)} chunks seeded. Embedding model: all-MiniLM-L6-v2 (384 dims).")
