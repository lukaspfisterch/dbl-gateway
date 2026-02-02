from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from typing import Deque, Literal

from .models import EventRecord

JobType = Literal["case.ingest", "case.embed", "case.index", "chat.message"]

JOB_TYPES: tuple[JobType, ...] = ("case.ingest", "case.embed", "case.index", "chat.message")
NON_LLM_JOB_TYPES: tuple[JobType, ...] = ("case.ingest", "case.embed", "case.index")


class JobQueueFull(Exception):
    pass


@dataclass(frozen=True)
class Job:
    job_id: str
    job_type: JobType
    thread_id: str
    turn_id: str
    user_id: str
    created_ts_utc: str
    priority: int
    payload_ref: str


@dataclass(frozen=True)
class JobWork:
    job: Job
    intent_event: EventRecord
    correlation_id: str
    trace_id: str


class JobRouter:
    def __init__(self, *, queue_max: int) -> None:
        self._queue_max = queue_max
        self._queues: dict[JobType, asyncio.Queue[JobWork]] = {
            job_type: asyncio.Queue(maxsize=queue_max) for job_type in NON_LLM_JOB_TYPES
        }
        self._llm_by_user: dict[str, Deque[JobWork]] = {}
        self._llm_round_robin: Deque[str] = deque()
        self._llm_pending = 0
        self._cond = asyncio.Condition()

    @property
    def queue_max(self) -> int:
        return self._queue_max

    def pending_counts(self) -> dict[str, int]:
        counts = {job_type: queue.qsize() for job_type, queue in self._queues.items()}
        counts["chat.message"] = self._llm_pending
        return counts

    def pending_count(self, job_type: JobType) -> int:
        if job_type == "chat.message":
            return self._llm_pending
        return self._queues[job_type].qsize()

    def llm_queue_position(self, user_id: str) -> int | None:
        queue = self._llm_by_user.get(user_id)
        if not queue:
            return None
        try:
            return list(self._llm_round_robin).index(user_id) + 1
        except ValueError:
            return None

    async def enqueue(self, job_work: JobWork) -> None:
        job_type = job_work.job.job_type
        if job_type == "chat.message":
            if self._llm_pending >= self._queue_max:
                raise JobQueueFull("llm queue full")
            queue = self._llm_by_user.get(job_work.job.user_id)
            if queue is None:
                queue = deque()
                self._llm_by_user[job_work.job.user_id] = queue
                self._llm_round_robin.append(job_work.job.user_id)
            queue.append(job_work)
            self._llm_pending += 1
            async with self._cond:
                self._cond.notify_all()
            return

        queue = self._queues[job_type]
        try:
            queue.put_nowait(job_work)
        except asyncio.QueueFull as exc:
            raise JobQueueFull("queue full") from exc
        async with self._cond:
            self._cond.notify_all()

    async def next_job(self) -> JobWork:
        while True:
            job = self._try_pop()
            if job is not None:
                return job
            async with self._cond:
                await self._cond.wait()

    async def next_llm_job(self) -> JobWork:
        while True:
            job = self._pop_llm()
            if job is not None:
                return job
            async with self._cond:
                await self._cond.wait()

    async def next_non_llm_job(self) -> JobWork:
        while True:
            job = self._pop_non_llm()
            if job is not None:
                return job
            async with self._cond:
                await self._cond.wait()

    def _try_pop(self) -> JobWork | None:
        job = self._pop_llm()
        if job is not None:
            return job
        job = self._pop_non_llm()
        if job is not None:
            return job
        return None

    def _pop_non_llm(self) -> JobWork | None:
        for job_type in NON_LLM_JOB_TYPES:
            queue = self._queues[job_type]
            try:
                return queue.get_nowait()
            except asyncio.QueueEmpty:
                continue
        return None

    def _pop_llm(self) -> JobWork | None:
        if self._llm_pending == 0:
            return None
        for _ in range(len(self._llm_round_robin)):
            user_id = self._llm_round_robin.popleft()
            queue = self._llm_by_user.get(user_id)
            if not queue:
                continue
            job = queue.popleft()
            self._llm_pending -= 1
            if queue:
                self._llm_round_robin.append(user_id)
            else:
                self._llm_by_user.pop(user_id, None)
            return job
        return None
