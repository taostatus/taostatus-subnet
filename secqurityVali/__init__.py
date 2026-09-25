"""secqurityVali - submission validator for the security-agent subnet.

Accepts a Docker image file from a miner, proves it really is a well-formed
image, dry-runs it under hard limits, and records one row per submission in a
local SQLite database.

Deliberately independent of masxai/ (the LLM-key subnet): no imports cross
between the two packages in either direction.
"""

__version__ = "0.1.0"
