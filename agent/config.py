import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent


def load_json(relative_path):
    path = BASE / relative_path
    with path.open(encoding="utf-8") as file:
        return json.load(file)


SETTINGS = load_json("config/settings.json")
RULES = load_json("config/rules.json")
SYSTEM_PROMPT = (
    BASE / "prompts/system.txt"
).read_text(encoding="utf-8").strip()

# Allows local verification before Docker deployment.
STATE_DB = Path(
    os.environ.get("STATE_DB_PATH", SETTINGS["state_db_path"])
)

if not SYSTEM_PROMPT:
    raise ValueError("System prompt must not be empty.")

if not SETTINGS["instance_ids"]:
    raise ValueError("At least one allowed instance is required.")

if RULES["require_approval"] is not True:
    raise ValueError("This demo requires approval for recovery.")

SUPPORTED_ACTIONS = {"start_ec2_instance", "restart_apache"}

if not set(RULES["allowed_actions"]).issubset(SUPPORTED_ACTIONS):
    raise ValueError("Unsupported recovery action in rules.")

if SETTINGS["poll_interval_seconds"] < 10:
    raise ValueError("Monitoring interval must be at least 10 seconds.")

if __name__ == "__main__":
    print("Configuration loaded successfully.")
    print("Web Region:", SETTINGS["aws_region"])
    print("Allowed instances:", len(SETTINGS["instance_ids"]))
    print("Approval required:", RULES["require_approval"])
    print("Allowed actions:", ", ".join(RULES["allowed_actions"]))