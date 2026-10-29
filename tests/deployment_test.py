"""Exercise actual Ansible staging, activation and recovery against temporary files.

Service management and readiness outcomes are simulated. Configuration validation
uses the real Go binary. Host-only ownership/capability operations are adapted for
an unprivileged local run; no system files or real services are changed.
"""
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VALID_CONFIG = """listen_addr: 127.0.0.1:15353
resolver_unfiltered:
  protocol: udp
  addr: 127.0.0.1:15354
"""


class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ansible = shutil.which("ansible-playbook")
        if not cls.ansible:
            raise RuntimeError("ansible-playbook must be on PATH")
        cls.build = tempfile.TemporaryDirectory(prefix="dnsfilter-deploy-build-")
        cls.binary = Path(cls.build.name) / "dns-filter"
        subprocess.run(["go", "build", "-o", str(cls.binary), "./service"], cwd=ROOT, check=True)
        cls.addClassCleanup(cls.build.cleanup)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dnsfilter-deploy-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.state_path = self.work / "state.json"
        self.config = self.work / "live.yml"
        self.binary_path = self.work / "live-binary"
        self.unit = self.work / "dns-filter.service"
        self.resolver = self.work / "resolv.conf"
        self.resolver_target = self.work / "original-resolver"
        self.resolver_target.write_text("nameserver 8.8.8.8\n")
        self.resolver.symlink_to(self.resolver_target)
        self.config.write_text(VALID_CONFIG)
        self.config.chmod(0o600)
        self.unit.write_text("previous systemd unit\n")
        self.candidate_config = self.work / "candidate.yml"
        self.candidate_config.write_text(VALID_CONFIG + "# new configuration\n")
        self.candidate_binary = self.work / "candidate-binary"
        self.write_binary(self.binary_path, False)
        self.write_binary(self.candidate_binary, False)
        self.state_path.write_text(json.dumps({
            "running": True, "healthy": True, "enabled": True, "starts": 0,
            "events": [], "config": str(self.config), "resolver": str(self.resolver),
        }))
        self.previous_binary = self.binary_path.read_bytes()
        self.previous_unit = self.unit.read_bytes()
        self.variables = {
            "ansible_python_interpreter": shutil.which("python3"),
            "service_name": "dnsfilter-isolated-test",
            "service_user": pwd.getpwuid(os.getuid()).pw_name,
            "service_group": grp.getgrgid(os.getgid()).gr_name,
            "target_bin": str(self.binary_path),
            "target_config": str(self.config),
            "target_service_file": str(self.unit),
            "target_resolv_conf": str(self.resolver),
            "local_binary_path": str(self.candidate_binary),
            "local_config_path": str(self.candidate_config),
            "use_local_dns": False, "wg_enabled": False,
            "deployment_components": ["config", "dns"],
            "deployment_probe_retries": 1, "deployment_probe_delay": 0,
            "test_state_path": str(self.state_path),
        }
        (self.work / "templates").symlink_to(ROOT / "templates", target_is_directory=True)
        tasks = self.work / "tasks"
        tasks.mkdir()
        for name in ["deploy.yml", "rollback.yml"]:
            text = (ROOT / "tasks" / name).read_text()
            text = re.sub(r"(?m)^(\s*)systemd:$", r"\1mock_systemd:", text)
            text = re.sub(r"(?m)^(\s*)service_facts:$", r"\1mock_service_facts:", text)
            text = text.replace("become: yes", "become: no")
            text = text.replace("owner: root", "owner: " + self.variables["service_user"])
            text = text.replace("group: root", "group: " + self.variables["service_group"])
            text = text.replace('argv: [setcap, "cap_net_bind_service=+ep", "{{ deployment_stage.path }}/install"]',
                                "argv: [/usr/bin/true]")
            (tasks / name).write_text(text)

    def write_binary(self, path, broken):
        script = f"""#!{shutil.which('python3')}
import json
import os
from pathlib import Path
import sys
state_path = Path({str(self.state_path)!r})
state = json.loads(state_path.read_text())
if sys.argv[1] == '-checkConfig':
    os.execv({str(self.binary)!r}, [{str(self.binary)!r}] + sys.argv[1:])
elif sys.argv[1] == '-test-start':
    state['healthy'] = not {broken!r} and '# runtime-fail' not in Path(state['config']).read_text()
elif sys.argv[1] == '-checkDNS':
    state['events'].append({{'probe': sys.argv[2], 'resolver': Path(state['resolver']).read_text()}})
    state_path.write_text(json.dumps(state))
    healthy = state.get('foreign_dns') or (state['running'] and state['healthy'])
    sys.exit(0 if healthy and sys.argv[2] != state.get('fail_probe_address') else 1)
state_path.write_text(json.dumps(state))
"""
        path.write_text(script)
        path.chmod(0o755)

    def change_state(self, **values):
        state = json.loads(self.state_path.read_text())
        state.update(values)
        self.state_path.write_text(json.dumps(state))

    def deploy(self):
        playbook = [{"hosts": "localhost", "gather_facts": False,
                     "vars": self.variables,
                     "tasks": [{"import_tasks": "tasks/deploy.yml", "tags": ["always"]}]}]
        path = self.work / "playbook.json"
        path.write_text(json.dumps(playbook))
        env = dict(os.environ,
                   ANSIBLE_HOME=str(self.work / "ansible-home"),
                   ANSIBLE_LOCAL_TEMP=str(self.work / "controller-tmp"),
                   ANSIBLE_REMOTE_TEMP=str(self.work / "remote-tmp"),
                   ANSIBLE_ACTION_PLUGINS=str(ROOT / "tests" / "ansible_plugins"),
                   ANSIBLE_NOCOLOR="1")
        result = subprocess.run([self.ansible, "-i", "localhost,", "-c", "local", str(path),
                                 "--tags", ",".join(self.variables["deployment_components"])],
                                env=env, text=True, capture_output=True, timeout=90)
        self.output = result.stdout + result.stderr
        self.assertIn("PLAY RECAP", self.output, self.output)
        self.state = json.loads(self.state_path.read_text())
        return result.returncode

    def assert_restored(self):
        self.assertEqual(self.config.read_text(), VALID_CONFIG, self.output)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.binary_path.read_bytes(), self.previous_binary)
        self.assertEqual(self.unit.read_bytes(), self.previous_unit)
        self.assertTrue(self.resolver.is_symlink(), self.output)
        self.assertEqual(self.resolver.readlink(), self.resolver_target)
        self.assertEqual(self.resolver.read_text(), "nameserver 8.8.8.8\n")
        self.assertTrue(self.state["running"], self.output)
        self.assertTrue(self.state["healthy"], self.output)

    def test_invalid_config_never_changes_live_files_or_service(self):
        self.candidate_config.write_text("listen_addr: 127.0.0.1:53\n")
        self.assertNotEqual(self.deploy(), 0, self.output)
        self.assert_restored()
        self.assertEqual(self.state["events"], [])
        self.assertEqual(list(self.work.glob(".dnsfilter-deploy-*")), [])

    def test_config_update_switches_dns_only_after_readiness(self):
        self.assertEqual(self.deploy(), 0, self.output)
        self.assertEqual(self.config.read_bytes(), self.candidate_config.read_bytes())
        self.assertEqual(self.binary_path.read_bytes(), self.previous_binary)
        self.assertEqual(self.unit.read_bytes(), self.previous_unit)
        probes = [e for e in self.state["events"] if "probe" in e]
        self.assertTrue(probes, self.output)
        self.assertTrue(all(e["resolver"] == "nameserver 8.8.8.8\n" for e in probes))
        self.assertEqual(self.resolver.read_text(), "nameserver 1.1.1.2\n")
        self.assertEqual(list(self.work.glob(".dnsfilter-deploy-*")), [])

    def test_failed_readiness_restores_config_and_service(self):
        self.candidate_config.write_text(VALID_CONFIG + "# runtime-fail\n")
        self.assertNotEqual(self.deploy(), 0, self.output)
        self.assert_restored()
        self.assertIn("Previous deployment restored.", self.output)

    def test_failed_full_upgrade_restores_binary_and_unit(self):
        self.variables["deployment_components"] = ["binary", "config", "dns"]
        self.write_binary(self.candidate_binary, True)
        os.setxattr(self.binary_path, b"user.dnsfilter_test", b"previous metadata")
        self.assertNotEqual(self.deploy(), 0, self.output)
        self.assert_restored()
        self.assertIn("Previous deployment restored.", self.output)
        self.assertEqual(os.getxattr(self.binary_path, b"user.dnsfilter_test"), b"previous metadata")

    def test_local_dns_switch_requires_loopback_port_53(self):
        self.variables["use_local_dns"] = True
        self.change_state(fail_probe_address="127.0.0.1:53")
        self.assertNotEqual(self.deploy(), 0, self.output)
        self.assert_restored()
        self.assertTrue(any(e.get("probe") == "127.0.0.1:53" for e in self.state["events"]))

    def test_foreign_dns_listener_cannot_hide_failed_service(self):
        self.candidate_config.write_text(VALID_CONFIG + "# runtime-fail\n")
        self.change_state(foreign_dns=True)
        self.assertNotEqual(self.deploy(), 0, self.output)
        self.assert_restored()
        self.assertIn("Previous deployment restored.", self.output)

    def test_failed_first_install_removes_new_files(self):
        self.variables["deployment_components"] = ["binary", "config", "dns"]
        self.write_binary(self.candidate_binary, True)
        for path in [self.binary_path, self.config, self.unit]:
            path.unlink()
        self.change_state(running=False, enabled=False)
        self.assertNotEqual(self.deploy(), 0, self.output)
        for path in [self.binary_path, self.config, self.unit]:
            self.assertFalse(path.exists(), self.output)
        self.assertTrue(self.resolver.is_symlink(), self.output)
        self.assertFalse(self.state["running"])
        self.assertFalse(self.state["enabled"])
        self.assertIn("Previous deployment restored.", self.output)

    def test_incomplete_rollback_retains_recovery_files(self):
        self.candidate_config.write_text(VALID_CONFIG + "# runtime-fail\n")
        self.change_state(fail_rollback=True)
        self.assertNotEqual(self.deploy(), 0, self.output)
        backups = list(self.work.glob(".dnsfilter-deploy-*/previous-config"))
        self.assertEqual(len(backups), 1, self.output)
        self.assertEqual(backups[0].read_text(), VALID_CONFIG)
        self.assertIn("rollback was incomplete", self.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
