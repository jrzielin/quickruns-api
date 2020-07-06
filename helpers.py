from flask_sqlalchemy import Pagination
from dateutil import parser

def serialize_list(x):
    if isinstance(x, Pagination):
        return [y.serialize() for y in x.items]
    return [y.serialize() for y in x]

def parse_int(x):
    if x is None:
        return 0
    try:
        y = int(x)
    except ValueError:
        y = 0
    return y

def parse_float(x):
    if x is None:
        return 0
    try:
        y = float(x)
    except ValueError:
        y = 0
    return y

def parse_datetime(x):
    if x is None:
        return None
    try:
        y = parser.parse(x)
    except:
        y = None
    return y

def parse_units(x):
    if not x or x not in {'mi', 'm', 'km'}:
        return 'mi'
    return x

def parse_title(x):
    if not x:
        return 'Normal Run'
    else:
        return x

def make_query(db, q):
    results = db.engine.execute(q.get_sql())
    return [dict(r.items()) for r in results]