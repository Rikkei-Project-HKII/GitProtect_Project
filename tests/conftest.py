import os
import time

os.environ.setdefault("GITPROTECT_AES_MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

try:
    import lupa
except ImportError:
    try:
        import fakeredis
        from fakeredis._clients._sync import FakeRedis
        from fakeredis.aioredis import FakeRedis as AsyncFakeRedis

        def custom_eval(self, script, numkeys, *keys_and_args):
            keys = list(keys_and_args[:numkeys])
            argv = list(keys_and_args[numkeys:])
            if 'local existing =' in script:
                existing = self.get(keys[2])
                if existing:
                    return existing
                self.set(keys[0], argv[1])
                self.set(keys[2], argv[0])
                self.zadd(keys[1], {argv[0]: 0})
                return argv[0]
            elif 'finished' in script:
                lease = self.get(keys[2])
                if lease != argv[1]:
                    return 0
                if argv[3] == 'finished':
                    self.set(keys[1], argv[2], ex=int(argv[5]))
                    self.zrem(keys[0], argv[0])
                    self.delete(keys[2], keys[3])
                else:
                    self.set(keys[1], argv[2])
                    self.expire(keys[2], int(argv[4]))
                    self.zadd(keys[0], {argv[0]: time.time() + float(argv[4])})
                return 1
            elif 'ZRANGEBYSCORE' in script:
                items = self.zrangebyscore(keys[0], '-inf', '+inf', start=0, num=1)
                if not items:
                    return None
                jid = items[0]
                now_ts = time.time()
                self.set('scan:lease:' + jid, argv[0], ex=int(argv[1]))
                self.zadd(keys[0], {jid: now_ts + float(argv[1])})
                return jid
            elif 'LINDEX' in script and 'LPOP' in script:
                if self.lindex(keys[0], 0) == argv[0]:
                    return self.lpop(keys[0])
                return None
            elif 'RPUSH' in script:
                if self.exists(keys[0]):
                    return 0
                self.set(keys[0], 1, ex=86400)
                for val in argv:
                    self.rpush(keys[1], val)
                return 1
            raise NotImplementedError('Unknown lua script: ' + script)

        async def async_custom_eval(self, script, numkeys, *keys_and_args):
            keys = list(keys_and_args[:numkeys])
            argv = list(keys_and_args[numkeys:])
            if 'RPUSH' in script:
                if await self.exists(keys[0]):
                    return 0
                await self.set(keys[0], 1, ex=86400)
                for val in argv:
                    await self.rpush(keys[1], val)
                return 1
            raise NotImplementedError('Unknown async lua script: ' + script)

        FakeRedis.eval = custom_eval
        AsyncFakeRedis.eval = async_custom_eval
    except ImportError:
        pass
