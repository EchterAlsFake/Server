"""Aggregate telemetry isolated from business transactions and personal data.

Redis owns production counters; its persistence policy controls durability.
Development uses process-local counters. No request performs a SQL commit.
"""
from datetime import datetime, timezone
from threading import Lock

from redis import Redis
from redis.exceptions import RedisError

FIELDS = ("total_requests", "total_bytes_in", "total_bytes_out")


class RequestStatistics:
    def __init__(self, app):
        self.logger = app.logger
        uri = app.config["RATELIMIT_STORAGE_URI"]
        self.redis = Redis.from_url(uri, socket_timeout=1, socket_connect_timeout=1) if uri.startswith(("redis://", "rediss://")) else None
        self.key = "pf-server:statistics:v1"
        self.lock = Lock()
        self.values = dict.fromkeys(FIELDS, 0)
        self.values["server_started_at"] = datetime.now(timezone.utc).isoformat()

    def increment(self, requests, bytes_in, bytes_out):
        increments = (requests, bytes_in, bytes_out)
        if self.redis:
            try:
                with self.redis.pipeline() as pipe:
                    pipe.hsetnx(self.key, "server_started_at", self.values["server_started_at"])
                    for field, value in zip(FIELDS, increments):
                        if value:
                            pipe.hincrby(self.key, field, value)
                    pipe.execute()
            except RedisError:
                self.logger.warning("Aggregate statistics unavailable")
        else:
            with self.lock:
                for field, value in zip(FIELDS, increments):
                    self.values[field] += value

    def snapshot(self):
        if self.redis:
            try:
                values = self.redis.hgetall(self.key)
                return dict(zip(FIELDS, (int(values.get(field.encode(), 0)) for field in FIELDS)),
                    server_started_at=values.get(b"server_started_at", self.values["server_started_at"].encode()).decode())
            except RedisError:
                self.logger.warning("Aggregate statistics unavailable")
        with self.lock:
            return dict(self.values)

    def reset(self):
        values = dict.fromkeys(FIELDS, 0)
        values["server_started_at"] = datetime.now(timezone.utc).isoformat()
        if self.redis:
            self.redis.hset(self.key, mapping=values)
        with self.lock:
            self.values = values
