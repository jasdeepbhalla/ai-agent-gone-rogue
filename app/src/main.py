from fastapi import FastAPI, HTTPException
from .db import get_reservations, healthcheck
from .auth import verify_token

app = FastAPI(title="rentalops-api")


@app.get("/health")
def health():
    return healthcheck()


@app.get("/reservations")
def reservations(token: str, partner_id: str):
    if not verify_token(token):
        raise HTTPException(401, "invalid partner token")
    return get_reservations(partner_id)
