import os
import psycopg2

DSN = (
    f"host={os.environ['DB_HOST']} dbname={os.environ['DB_NAME']} "
    f"user={os.environ['DB_USER']} password={os.environ['DB_PASS']}"
)


def _conn():
    return psycopg2.connect(DSN, connect_timeout=5)


def healthcheck():
    with _conn() as c, c.cursor() as cur:
        cur.execute("select count(*) from reservations")
        return {"status": "ok", "reservations": cur.fetchone()[0]}


def get_reservations(partner_id):
    with _conn() as c, c.cursor() as cur:
        cur.execute(
            "select id, customer, vehicle, pickup, dropoff, amount "
            "from reservations where customer like %s limit 200",
            (f"%{partner_id}%",),
        )
        return [dict(zip(("id", "customer", "vehicle", "pickup", "dropoff", "amount"), r))
                for r in cur.fetchall()]
