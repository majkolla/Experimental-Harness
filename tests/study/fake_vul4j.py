"""A fake `docker` that behaves like the Vul4J image on disk (checked against the
Vul4J source, commit 376411d): containers started with `run -d ... sleep
infinity` and driven with `exec`, the checkout layout, vulnerability_info.json,
the vulnerable/human_patch copies with paths.json, `apply -v human_patch`,
`compile`, and JUnit reports from `test -b all|povs`."""

import json
import pathlib
import shutil


class FakeDocker:
    """`project` = {"main": path, "test": path, "vuln": text, "fixed": text, "pov": name,
    "info": {...}, "report": fn(main_text) -> xml, "report_dir": rel}"""

    def __init__(self, project, cve, image, fail_on=None):
        self.p, self.cve, self.image = project, cve, image
        self.fail_on = fail_on
        self.seen = []          # every argv
        self.cmds = []          # the vul4j/sh/python command lines run in containers
        self.containers = {}    # name -> workspace
        self.started = 0
        self.info_seen = None   # vulnerability_info.json after the runner's rewrite

    def __call__(self, argv, timeout=None):
        self.seen.append(argv)
        assert argv[0] == "docker" and timeout
        if argv[1] == "run" and "-d" in argv:
            name = argv[argv.index("--name") + 1]
            ws = pathlib.Path(argv[argv.index("-v") + 1].rsplit(":", 1)[0])
            assert argv[argv.index(self.image) + 1:] == ["sleep", "infinity"]
            self.containers[name] = ws
            self.started += 1
            return 0, name + "\n", ""
        if argv[1] == "rm":
            self.containers.pop(argv[-1], None)
            return 0, "", ""
        if argv[1] == "run":   # throwaway container: workspace removal
            ws = pathlib.Path(argv[argv.index("-v") + 1].rsplit(":", 1)[0])
            return self._shell(ws, argv[argv.index(self.image) + 1:])
        assert argv[1] == "exec", argv
        ws = self.containers[argv[2]]
        cmd = argv[3:]
        if cmd[0] == "timeout":
            assert cmd[1:3] == ["-k", "30"]
            cmd = cmd[4:]
        line = " ".join(cmd)
        self.cmds.append(line)
        if self.fail_on and line.startswith(self.fail_on):
            code = self.fail_on_code if hasattr(self, "fail_on_code") else 1
            return code, "", "boom"
        return self._vul4j(ws, cmd) if cmd[0] == "vul4j" else self._shell(ws, cmd)

    def _vul4j(self, ws, cmd):
        p, src = self.p, ws / "src"
        if cmd[1] == "checkout":
            assert cmd == ["vul4j", "checkout", "--id", self.cve, "-d", "/ws/src"]
            for rel, text in ((p["main"], p["vuln"]), (p["test"], "class HTest {}\n")):
                (src / rel).parent.mkdir(parents=True, exist_ok=True)
                (src / rel).write_text(text)
            v = src / "VUL4J"
            base = pathlib.PurePosixPath(p["main"]).name
            for version, text in (("vulnerable", p["vuln"]), ("human_patch", p["fixed"])):
                (v / version).mkdir(parents=True)
                (v / version / base).write_text(text)
                (v / version / "paths.json").write_text(json.dumps({base: p["main"]}))
            (v / "vulnerability_info.json").write_text(json.dumps(p["info"], indent=2))
        elif cmd[1] == "apply":
            assert cmd == ["vul4j", "apply", "-d", "/ws/src", "-v", "human_patch"]
            base = pathlib.PurePosixPath(p["main"]).name
            shutil.copy(src / "VUL4J/human_patch" / base, src / p["main"])
        elif cmd[1] == "compile":
            assert cmd == ["vul4j", "compile", "-d", "/ws/src"]
            (src / "VUL4J" / "compile.log").write_text("BUILD SUCCESS\n")
        elif cmd[1] == "test":
            assert cmd[2:4] == ["-d", "/ws/src"] and cmd[4] == "-b" and cmd[5] in ("all", "povs")
            from hp.bank import vul4j
            for old in vul4j.find_reports(src):   # vul4j deletes old reports itself
                old.unlink()
            rep = src / p.get("report_dir", "target/surefire-reports")
            rep.mkdir(parents=True, exist_ok=True)
            (rep / "TEST-p.HTest.xml").write_text(p["report"]((src / p["main"]).read_text()))
        else:
            raise AssertionError(cmd)
        return 0, "", ""

    def _shell(self, ws, cmd):
        if cmd[:2] == ["python3", "-c"]:          # the runner's test_all_cmd rewrite
            info_p = ws / "src" / "VUL4J" / "vulnerability_info.json"
            code = cmd[2].replace("/ws/src", str(ws / "src"))
            exec(compile(code, "<patch-info>", "exec"), {})
            self.info_seen = json.loads(info_p.read_text())
            return 0, "", ""
        assert cmd[:2] == ["sh", "-c"], cmd
        script = cmd[2]
        if "cp -r /ws/patched/." in script:
            if (ws / "patched").is_dir():
                shutil.copytree(ws / "patched", ws / "src", dirs_exist_ok=True)
            for part in script.split("; ")[2:]:
                if part.startswith("rm -f "):
                    (ws / "src" / part[len("rm -f '/ws/src/"):-1]).unlink()
            return 0, "", ""
        if script.startswith("rm -rf /ws/*"):
            for child in ws.iterdir():
                shutil.rmtree(child) if child.is_dir() else child.unlink()
            return 0, "", ""
        raise AssertionError(script)
