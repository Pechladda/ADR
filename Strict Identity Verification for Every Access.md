# Title
Strict Identity Verification for Every Access

## Context
Access control is often overly dependent on existing sessions or network location, for example:
- Long-lived tokens that are not strongly bound to devices or context
- Requests from new IP addresses, countries, or devices still being accepted
- Excessive privileges that are not re-evaluated when risk conditions change



## Decision
Enforce strict identity verification for every access, meaning that each request to a protected resource must be strongly validated:
- Use short-lived access tokens with secure refresh mechanisms
- Apply step-up authentication (e.g., MFA or biometrics) for high-risk actions
- Require re-authentication when risk increases (new device, unusual location, administrative actions)
- Bind tokens to audience, scope, device, and session, and validate them on every request

## Rationale
- Access should not be treated as permanently granted based on a single login event.
- Reduces the impact of token or session hijacking.
- Increases confidence that each request truly comes from the same user, the same device, and an acceptable context.

## Consequences
Pros – What becomes easier?
- More granular and secure access control, especially for sensitive endpoints.
- Better balance between security and user experience through contextual step-up authentication.
- Reduced risk of replay attacks and long-term abuse of stolen tokens.

Cons – What becomes more difficult?
- Increased user friction due to MFA or step-up challenges under strict policies.
- Requires mature risk engines, device binding, and session management.
- Integration across SaaS, APIs, and mobile applications becomes more complex.

## Sample code
```python
import os
import time
import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic_settings import BaseSettings

class StrictAuthSettings(BaseSettings):
    jwt_public_key: str = os.getenv("JWT_PUBLIC_KEY", "your-public-key")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "RS256")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "api://my-service")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "https://idp.example.com")
    fresh_window_seconds: int = int(os.getenv("FRESH_WINDOW_SECONDS", 300))

settings = StrictAuthSettings()
app = FastAPI()
security = HTTPBearer()

def verify_strict_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(
            credentials.credentials,
            settings.jwt_public_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer
        )
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")

def require_fresh_mfa(claims: dict = Depends(verify_strict_token)):
    auth_time = claims.get("auth_time")
    amr = claims.get("amr", [])
    
    if not auth_time:
        raise HTTPException(status_code=403, detail="missing_auth_time")

    is_fresh = (time.time() - auth_time) <= settings.fresh_window_seconds
    has_mfa = any(method in amr for method in ["mfa", "otp", "webauthn"])

    if not (is_fresh and has_mfa):
        raise HTTPException(status_code=403, detail="step_up_required")

    return claims

@app.post("/admin/rotate-api-key")
def rotate_api_key(claims: dict = Depends(require_fresh_mfa)):
    return {"status": "ok", "message": "Strict Identity verified, key rotated"}

