"""python -m codesentinel ...  - same as the codesentinel command (works where .exe launchers are blocked)."""
from .cli import app

app(prog_name="codesentinel")
