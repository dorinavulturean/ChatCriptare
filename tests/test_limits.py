from server.limits import RateLimiter


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_burst_apoi_blocare():
    rl = RateLimiter(rate=1, burst=3, clock=FakeClock())
    assert [rl.allow() for _ in range(3)] == [True, True, True]
    assert rl.allow() is False


def test_se_reface_in_timp():
    clock = FakeClock()
    rl = RateLimiter(rate=2, burst=2, clock=clock)
    assert rl.allow()
    assert rl.allow()
    assert not rl.allow()
    clock.t += 1.0
    assert rl.allow()