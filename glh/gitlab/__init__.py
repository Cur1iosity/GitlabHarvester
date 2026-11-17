"""
Talking to GitLab: ClientFactory (factory) makes every python-gitlab client
from ClientSettings and Pacing (settings); GitLabConnection (connection) holds
the authenticated clients of a run (tokens, per-thread clients);
RateLimitMonitor (rate_monitor) accounts HTTP 429; plus request pacing
(throttling), User-Agents and the classification of API errors (errors).
"""
