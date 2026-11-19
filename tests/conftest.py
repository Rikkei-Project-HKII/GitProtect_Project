"""
Global Pytest Fixtures and Environment Configuration for GitProtect.
Provides:
1. Default GITPROTECT_AES_MASTER_KEY for tests.
2. In-memory Lua fallback emulation for fakeredis when lupa C-extension is unavailable on Windows.
"""
import os
import sys
import time
import json

# Ensure tests/ and root are in python path
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("tests"))

# Ensure AES Master Key is always present for testing
os.environ.setdefault(
    "GITPROTECT_AES_MASTER_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

# Patch fakeredis eval if lupa is not installed
try:
    import fakeredis
    import fakeredis.aioredis

    def _sync_execute_lua(redis_inst, script_str, keys, argv):
        # 1. Webhook dedup & enqueue script
        if "gitprotect:delivery" in script_str or "unpack(ARGV)" in script_str:
            set_ok = redis_inst.set(keys[0], "1", nx=True, ex=86400)
            if not set_ok:
                return 0
            if len(argv) > 0:
                redis_inst.rpush(keys[1], *argv)
            return 1

        # 2. initial_scan ENQUEUE script
        if "if existing then return existing end" in script_str:
            existing = redis_inst.get(keys[2])
            if existing:
                return existing if isinstance(existing, str) else existing.decode()
            redis_inst.set(keys[0], argv[1])
            redis_inst.set(keys[2], argv[0])
            redis_inst.zadd(keys[1], {argv[0]: 0})
            return argv[0]

        # 3. initial_scan CLAIM script
        if "ZRANGEBYSCORE" in script_str:
            now_ts = int(time.time())
            items = redis_inst.zrangebyscore(keys[0], "-inf", "+inf", start=0, num=1)
            if not items:
                return False
            job = items[0]
            if isinstance(job, bytes):
                job = job.decode()
            lease_time = int(argv[1])
            redis_inst.zadd(keys[0], {job: now_ts + lease_time})
            redis_inst.set("scan:lease:" + job, argv[0], ex=lease_time)
            return job

        # 4. initial_scan UPDATE script
        if "finished" in script_str or "~= ARGV[2]" in script_str:
            val = redis_inst.get(keys[2])
            if isinstance(val, bytes):
                val = val.decode()
            if val != argv[1]:
                return 0
            if argv[3] == "finished":
                redis_inst.set(keys[1], argv[2], ex=int(argv[5]))
                redis_inst.zrem(keys[0], argv[0])
                redis_inst.delete(keys[2], keys[3])
            else:
                redis_inst.set(keys[1], argv[2])
                redis_inst.expire(keys[2], int(argv[4]))
                redis_inst.zadd(keys[0], {argv[0]: int(time.time()) + int(argv[4])})
            return 1

        return 1

    async def _async_execute_lua(redis_inst, script_str, keys, argv):
        # 1. Webhook dedup & enqueue script
        if "gitprotect:delivery" in script_str or "unpack(ARGV)" in script_str:
            set_ok = await redis_inst.set(keys[0], "1", nx=True, ex=86400)
            if not set_ok:
                return 0
            if len(argv) > 0:
                await redis_inst.rpush(keys[1], *argv)
            return 1

        # Fallback to sync underlying store if needed
        return _sync_execute_lua(redis_inst, script_str, keys, argv)

    # Check if native eval works; if not, patch
    r_test = fakeredis.FakeRedis()
    needs_patch = False
    try:
        r_test.eval("return 1", 0)
    except Exception:
        needs_patch = True

    if needs_patch:
        def fake_eval(self, script, numkeys, *args):
            keys = [k.decode() if isinstance(k, bytes) else str(k) for k in args[:numkeys]]
            argv = [a.decode() if isinstance(a, bytes) else str(a) for a in args[numkeys:]]
            script_str = script.decode() if isinstance(script, bytes) else str(script)
            return _sync_execute_lua(self, script_str, keys, argv)

        async def fake_aio_eval(self, script, numkeys, *args):
            keys = [k.decode() if isinstance(k, bytes) else str(k) for k in args[:numkeys]]
            argv = [a.decode() if isinstance(a, bytes) else str(a) for a in args[numkeys:]]
            script_str = script.decode() if isinstance(script, bytes) else str(script)
            return await _async_execute_lua(self, script_str, keys, argv)

        fakeredis.FakeRedis.eval = fake_eval
        fakeredis.aioredis.FakeRedis.eval = fake_aio_eval

except ImportError:
    pass
