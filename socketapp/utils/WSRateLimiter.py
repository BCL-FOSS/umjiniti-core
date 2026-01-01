import time
import redis.asyncio as redis

class WSRateLimiter:
    def __init__(self, redis_host: str, redis_port: str):
        self.pipeline_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        # Rate limit settings
        self.MAX_TOKENS = 5          # Max messages per interval
        self.REFILL_INTERVAL = 10    # Seconds between refills

    async def check_rate_limit(self, client_id):
        """
        Token bucket algorithm using Redis:
        - Each client has a key in Redis storing their token count and last refill time.
        - If enough time has passed, refill tokens up to MAX_TOKENS.
        - If tokens available, decrement and allow.
        """
        key_tokens = f"rate:{client_id}:tokens"
        key_last = f"rate:{client_id}:last"

        now = int(time.time())

        # Start a Redis transaction (pipeline)
        pipe = self.pipeline_client.pipeline()
        pipe.get(key_tokens)
        pipe.get(key_last)
        tokens_str, last_str = await pipe.execute()

        tokens = int(tokens_str) if tokens_str else self.MAX_TOKENS
        last = int(last_str) if last_str else now

        # Refill logic
        elapsed = now - last
        if elapsed >= self.REFILL_INTERVAL:
            tokens = self.MAX_TOKENS
            last = now

        if tokens > 0:
            tokens -= 1
            # Store updated tokens and timestamp atomically
            await self.pipeline_client.mset({
                key_tokens: tokens,
                key_last: last
            })
            await self.pipeline_client.expire(key_tokens, self.REFILL_INTERVAL * 2)
            await self.pipeline_client.expire(key_last, self.REFILL_INTERVAL * 2)
            return True
        else:
            return False
