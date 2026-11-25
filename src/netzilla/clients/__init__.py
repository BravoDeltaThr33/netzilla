"""API clients.

One module per external service. Every public function is async, takes a
Services instance first, and returns an ApiResult — never raises for network
or HTTP problems.
"""
