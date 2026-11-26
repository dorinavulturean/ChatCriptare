import time


class RateLimiter:
    """Galeata cu jetoane: in medie `rate` mesaje pe secunda, cu un maxim de `burst` pe loc."""

    def __init__(self, rate=5.0, burst=10, clock=time.monotonic):
        self.rate = rate
        self.burst = burst
        self.clock = clock
        self.tokens = float(burst)
        self.last = clock()

    def allow(self):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False