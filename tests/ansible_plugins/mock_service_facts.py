"""Return only the fixture service; never inspect host services."""
import json
from pathlib import Path

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        state = json.loads(Path(task_vars["test_state_path"]).read_text())
        services = {}
        if Path(task_vars["target_service_file"]).exists():
            name = task_vars["service_name"] + ".service"
            services[name] = {
                "name": name,
                "state": "running" if state["running"] else "stopped",
                "status": "enabled" if state["enabled"] else "disabled",
                "source": "systemd",
            }
        return {"ansible_facts": {"services": services}}
