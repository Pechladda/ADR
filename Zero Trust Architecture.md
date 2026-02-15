# Title
Zero Trust Architecture

## Context
Traditional security models often assume that anything inside the internal network is trusted. If an attacker breaches the perimeter once, they can easily perform lateral movement to access other resources.
With the rise of cloud services, remote work, and SaaS, the network boundary is no longer clearly defined as in the past.


## Decision
Adopt a Zero Trust Architecture (ZTA) with the following principles:
- Never trust, always verify
- Validate every request based on identity, device, context, and risk
- Enforce least privilege, micro-segmentation, and continuous evaluation


## Rationale
- Limits the blast radius when a single account is compromised, since access is not implicitly trusted across the entire system.
- Fits well with hybrid environments (on-premises + cloud) and distributed workforces.
- Improves visibility, control, and auditing of access to resources.


## Consequences
Pros – What becomes easier?
- Better containment of attacks and reduced lateral movement.
- More fine-grained access control (per application/per resource) with clearer audit trails.
- Stronger support for remote work, BYOD, and cloud-native architectures.

Cons – What becomes more difficult?
- Requires investment in IAM, device posture management, policy engines, and logging/monitoring.
- Policy design becomes more complex and must be rolled out gradually to avoid degrading user experience.
- Accurate identity and asset inventory management becomes critical.

## Sample code
```python
import os
import jwt
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic_settings import BaseSettings

class ZTASettings(BaseSettings):
    jwt_public_key: str = os.getenv("JWT_PUBLIC_KEY", "your-public-key")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "RS256")

settings = ZTASettings()
app = FastAPI()
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(
            credentials.credentials, 
            settings.jwt_public_key, 
            algorithms=[settings.jwt_algorithm],
            options={"verify_aud": False}
        )
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")

class ZeroTrustPolicy:
    def __init__(self, required_scope: str):
        self.required_scope = required_scope

    def __call__(self, request: Request, claims: dict = Depends(verify_token)):

        if self.required_scope not in claims.get("scp", []):
            raise HTTPException(status_code=403, detail="insufficient_scope")

        device_posture = request.headers.get("x-device-posture", "")
        if "managed:true" not in device_posture or "jb:false" not in device_posture:
            raise HTTPException(status_code=403, detail="device_not_trusted")

        risk_score = int(request.headers.get("x-risk-score", 0))
        if risk_score >= 70:
            raise HTTPException(status_code=403, detail="high_risk_blocked")

        return claims

@app.get("/admin/reports")
def read_reports(claims: dict = Depends(ZeroTrustPolicy(required_scope="reports:read"))):
    return {"status": "ok", "sub": claims.get("sub")}

