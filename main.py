import hashlib
import json
import pathlib
import random
import sys
 
from harness import dispatch
 
 
def load(cfg_path):
    cfg = json.loads(pathlib.Path(cfg_path).read_text())
    root = pathlib.Path(cfg_path).parent
    cfg["_root"] = root
    cfg["_prompt"] = (root / cfg["prompt_file"]).read_text()
    cfg["_tasks"] = sorted(p for p in (root / cfg["tasks_dir"]).glob("*.txt"))
    return cfg
 
 
def build_schedule(cfg):
    """Pure function of the config. No I/O, no network. Auditable before spending."""
    calls = []
    for task in cfg["_tasks"]:
        for panel, seats in cfg["panels"].items():
            for rep in range(cfg["replicates"]):
                for seat, ref in enumerate(seats):
                    calls.append(
                        {
                            "call_id": f"{task.stem}|{panel}|r{rep}|s{seat}",
                            "task": task.stem,
                            "panel": panel,
                            "replicate": rep,
                            "seat": seat,
                            "model_ref": ref,
                            **cfg["models"][ref],
                        }
                    )
    # Global shuffle: a panel is a grouping in the design, not an event in time.
    random.Random(cfg["seed"]).shuffle(calls)
    return calls
 
 
def done_ids(log_path):
    if not log_path.exists():
        return set()
    return {json.loads(line)["call_id"] for line in log_path.open() if line.strip()}
 
 
def main(cfg_path):
    cfg = load(cfg_path)
    log_path = cfg["_root"] / cfg["log"]
    log_path.parent.mkdir(parents=True, exist_ok=True)
 
    schedule = build_schedule(cfg)
    already = done_ids(log_path)
    todo = [c for c in schedule if c["call_id"] not in already]
 
    prompt_hash = hashlib.sha256(cfg["_prompt"].encode()).hexdigest()[:12]
    print(f"{len(schedule)} calls, {len(already)} done, {len(todo)} to run")
 
    with log_path.open("a") as log:
        for i, call in enumerate(todo, 1):
            patch = (cfg["_root"] / cfg["tasks_dir"] / f"{call['task']}.txt").read_text()
            prompt = cfg["_prompt"].replace("{{PATCH}}", patch)
            result = dispatch(
                call["provider"], call["model"], prompt, cfg["temperature"]
            )
            record = {
                **call,
                **result,
                "experiment": cfg["name"],
                "temperature": cfg["temperature"],
                "prompt_hash": prompt_hash,
            }
            log.write(json.dumps(record) + "\n")
            log.flush()
            print(f"[{i}/{len(todo)}] {call['call_id']} {result['status']}")
 
 
if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "experiment.json")