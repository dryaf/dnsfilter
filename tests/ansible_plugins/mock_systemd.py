"""Local deployment-test adapter; never contacts the host's service manager."""
import json
import subprocess
from pathlib import Path

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        path = Path(task_vars["test_state_path"])
        state = json.loads(path.read_text())
        state["events"].append({"service": args})
        if args.get("name"):
            if args["name"] != task_vars["service_name"]:
                return {"failed": True, "msg": "unexpected service in isolated test"}
            if "enabled" in args:
                state["enabled"] = args["enabled"]
            action = args.get("state")
            if action == "stopped":
                state["running"] = False
            elif action == "restarted" or (action == "started" and not state["running"]):
                if state.get("fail_rollback") and state["starts"] > 0:
                    path.write_text(json.dumps(state))
                    return {"failed": True, "msg": "injected rollback activation failure"}
                state["starts"] += 1
                state["running"] = True
                path.write_text(json.dumps(state))
                result = subprocess.run([task_vars["target_bin"], "-test-start"], check=False)
                return {"changed": True, "failed": result.returncode != 0}
        path.write_text(json.dumps(state))
        return {"changed": True, "status": {
            "ActiveState": "active" if state["running"] and state["healthy"] else "failed",
            "SubState": "running" if state["running"] and state["healthy"] else "failed",
        }}
