"""Bounded keyset pages. Cursor contents are validated data, never SQL."""
from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Any, Callable

from sqlalchemy import and_, or_


class InvalidCursor(ValueError):
    pass


def paginate(query, columns: tuple, *, limit: int, cursor: str | None, scope: str,
             descending: bool = True, key: Callable[[Any], tuple] | None = None):
    if not 1 <= limit <= 200:
        raise InvalidCursor('Page limit must be between 1 and 200')
    total = query.order_by(None).count()
    if cursor is not None:
        try:
            if not cursor or len(cursor) > 2048:
                raise ValueError
            data = json.loads(base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True))
            if not isinstance(data, dict) or data.get('v') != 1 or data.get('scope') != scope:
                raise ValueError
            values = data['keys']
            if not isinstance(values, list) or len(values) != len(columns):
                raise ValueError
            decoded = []
            for column, value in zip(columns, values):
                expected = column.type.python_type
                if expected is datetime:
                    if not isinstance(value, str):
                        raise ValueError
                    value = datetime.fromisoformat(value)
                elif type(value) is not expected or (expected is int and value < 1):
                    raise ValueError
                decoded.append(value)
        except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error, OverflowError):
            raise InvalidCursor('Invalid cursor for this endpoint or filter') from None
        query = query.filter(or_(*[
            and_(*(columns[j] == decoded[j] for j in range(i)),
                 columns[i] < decoded[i] if descending else columns[i] > decoded[i])
            for i in range(len(columns))
        ]))
    order = [column.desc() if descending else column.asc() for column in columns]
    rows = query.order_by(None).order_by(*order).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more:
        values = key(rows[-1]) if key else tuple(getattr(rows[-1], column.key) for column in columns)
        payload = {'v': 1, 'scope': scope, 'keys': [value.isoformat() if isinstance(value, datetime) else value for value in values]}
        next_cursor = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    return rows, {'limit': limit, 'next_cursor': next_cursor, 'has_more': has_more, 'total': total}
