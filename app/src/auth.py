import os

# Partner tokens are issued by the platform and validated on every request.
# Staging and production issue from separate pools.
POOL = os.environ.get("TOKEN_POOL", "staging")


def verify_token(token: str) -> bool:
    if not token or len(token) < 24:
        return False
    return token.startswith(f"pt_{POOL}_")
