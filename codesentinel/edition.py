"""Which edition this is. The public GitHub edition has no AI engine (false-positive model, local AI finder and
AI-written fixes); everything else - scanners, filters, rule-based fixes, threat model, reports - is the same."""
EDITION = "public"
HAS_AI = EDITION == "full"
PUBLIC_AI_MESSAGE = ("The AI engine (false-positive model, AI finder and AI-written fixes) is not included in the "
                     "public edition of CodeSentinel.")
