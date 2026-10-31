#!/usr/bin/env python3
import sys
import os
import yaml
import uuid
import hashlib
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

def get_hwid() -> str:
    machine_id_paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
    for p in machine_id_paths:
        if os.path.exists(p):
            with open(p) as f:
                return f.read().strip()
    return str(uuid.getnode())

def sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()

def generate_key() -> bytes:
    return os.urandom(32)

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, None)

def load_yaml_safe(path: str) -> dict:
    if path.endswith(".yml"):
        tmp = path[:-4] + ".yaml"
        shutil.copy2(path, tmp)
        try:
            with open(tmp, "r") as f:
                data = yaml.safe_load(f)
        finally:
            os.remove(tmp)
    else:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    if not isinstance(data, dict):
        data = {}
    return data

def load_ydb(ydb_path: str, key_path: str = None) -> tuple:
    with open(ydb_path, "rb") as f:
        raw = f.read()
    key_hash_line_end = raw.index(b"\n")
    stored_hash = raw[:key_hash_line_end].decode().strip()
    blob = raw[key_hash_line_end + 1:]
    if key_path is None:
        raise SystemExit(f"file is locked — run: ydb -u {ydb_path} <file.key>")
    with open(key_path, "rb") as f:
        key = f.read()
    if sha512(key) != stored_hash:
        raise SystemExit("key mismatch")
    plaintext = decrypt(blob, key)
    data = yaml.safe_load(plaintext.decode())
    hwid = get_hwid()
    allowed = data.get("_allowedHWID", [])
    if hwid not in allowed:
        raise SystemExit(f"HWID not authorized — run: ydb -u {ydb_path} <file.key>")
    return data, key, stored_hash

def save_ydb(ydb_path: str, data: dict, key: bytes):
    plaintext = yaml.dump(data, default_flow_style=False).encode()
    blob = encrypt(plaintext, key)
    key_hash = sha512(key).encode() + b"\n"
    with open(ydb_path, "wb") as f:
        f.write(key_hash + blob)

def resolve_path(data: dict, path: str):
    parts = path.split(".")
    node = data
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            raise SystemExit(f"path not found: {path}")
        node = node[p]
    return node

def set_path(data: dict, path: str, value):
    parts = path.split(".")
    node = data
    for p in parts[:-1]:
        if p not in node:
            node[p] = {}
        node = node[p]
    node[parts[-1]] = value

def del_path(data: dict, path: str):
    parts = path.split(".")
    node = data
    for p in parts[:-1]:
        if not isinstance(node, dict) or p not in node:
            raise SystemExit(f"path not found: {path}")
        node = node[p]
    if parts[-1] not in node:
        raise SystemExit(f"path not found: {path}")
    del node[parts[-1]]

def cmd_compile(yml_path: str, out_path: str = None):
    data = load_yaml_safe(yml_path)
    key = generate_key()
    key_hash = sha512(key)
    hwid = get_hwid()
    data["_keyHash"] = key_hash
    data["_allowedHWID"] = [hwid]
    plaintext = yaml.dump(data, default_flow_style=False).encode()
    blob = encrypt(plaintext, key)
    if out_path:
        stem = str(Path(out_path).with_suffix(""))
        ydb_path = out_path if out_path.endswith(".ydb") else out_path + ".ydb"
    else:
        stem = Path(yml_path).stem
        ydb_path = stem + ".ydb"
    key_path = Path(ydb_path).stem + ".key"
    with open(ydb_path, "wb") as f:
        f.write(key_hash.encode() + b"\n" + blob)
    with open(key_path, "wb") as f:
        f.write(key)
    print(f"compiled: {ydb_path}")
    print(f"key:      {key_path}")

def cmd_unlock(ydb_path: str, key_path: str):
    with open(ydb_path, "rb") as f:
        raw = f.read()
    key_hash_line_end = raw.index(b"\n")
    stored_hash = raw[:key_hash_line_end].decode().strip()
    blob = raw[key_hash_line_end + 1:]
    with open(key_path, "rb") as f:
        key = f.read()
    if sha512(key) != stored_hash:
        raise SystemExit("key mismatch")
    plaintext = decrypt(blob, key)
    data = yaml.safe_load(plaintext.decode())
    hwid = get_hwid()
    allowed = data.get("_allowedHWID", [])
    if hwid in allowed:
        print("HWID already authorized")
        return
    allowed.append(hwid)
    data["_allowedHWID"] = allowed
    save_ydb(ydb_path, data, key)
    print(f"HWID added: {hwid}")

def cmd_decompile(ydb_path: str, key_path: str):
    data, key, _ = load_ydb(ydb_path, key_path)
    clean = {k: v for k, v in data.items() if not k.startswith("_")}
    print(yaml.dump(clean, default_flow_style=False), end="")

def cmd_genkey(ydb_path: str):
    ans = input("old file.key will be permanently invalid. continue? [y/N] ").strip().lower()
    if ans != "y":
        print("aborted")
        return
    with open(ydb_path, "rb") as f:
        raw = f.read()
    key_hash_line_end = raw.index(b"\n")
    old_hash = raw[:key_hash_line_end].decode().strip()
    stem = Path(ydb_path).stem
    key_path = stem + ".key"
    if not os.path.exists(key_path):
        raise SystemExit(f"old key not found at {key_path} — cannot reencrypt")
    with open(key_path, "rb") as f:
        old_key = f.read()
    if sha512(old_key) != old_hash:
        raise SystemExit("key mismatch — cannot reencrypt")
    blob = raw[key_hash_line_end + 1:]
    plaintext = decrypt(blob, old_key)
    data = yaml.safe_load(plaintext.decode())
    new_key = generate_key()
    new_hash = sha512(new_key)
    data["_keyHash"] = new_hash
    save_ydb(ydb_path, data, new_key)
    with open(key_path, "wb") as f:
        f.write(new_key)
    print(f"key regenerated: {key_path}")

def cmd_get(ydb_path: str, key_path: str, path: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    result = resolve_path(data, path)
    print(yaml.dump(result, default_flow_style=False) if isinstance(result, dict) else result)

def cmd_add(ydb_path: str, key_path: str, table: str, record_id: str, template: str = None):
    data, key, _ = load_ydb(ydb_path, key_path)
    if table not in data:
        data[table] = {}
    if record_id in data[table]:
        raise SystemExit(f"record {record_id} already exists in {table}")
    if template:
        tmpl = data.get("_templates", {}).get(template)
        if tmpl is None:
            raise SystemExit(f"template not found: {template}")
        import copy
        data[table][record_id] = copy.deepcopy(tmpl)
    else:
        data[table][record_id] = {}
    save_ydb(ydb_path, data, key)
    print(f"added: {table}.{record_id}")

def cmd_append(ydb_path: str, key_path: str, path: str, kv: str):
    data, key, _ = load_ydb(ydb_path, key_path)
    parsed = yaml.safe_load(kv)
    node = resolve_path(data, path)
    if not isinstance(node, dict):
        raise SystemExit(f"{path} is not a dict")
    node.update(parsed)
    save_ydb(ydb_path, data, key)
    print(f"appended to {path}")

def cmd_remove(ydb_path: str, key_path: str, path: str):
    data, key, _ = load_ydb(ydb_path, key_path)
    del_path(data, path)
    save_ydb(ydb_path, data, key)
    print(f"removed: {path}")

def cmd_set(ydb_path: str, key_path: str, path: str, value: str):
    data, key, _ = load_ydb(ydb_path, key_path)
    parsed = yaml.safe_load(value)
    set_path(data, path, parsed)
    save_ydb(ydb_path, data, key)
    print(f"set: {path} = {parsed}")

def cmd_list(ydb_path: str, key_path: str, table: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    if table not in data:
        raise SystemExit(f"table not found: {table}")
    for k in data[table]:
        print(k)

def cmd_find(ydb_path: str, key_path: str, table: str, field: str, value: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    if table not in data:
        raise SystemExit(f"table not found: {table}")
    parsed_value = yaml.safe_load(value)
    for record_id, record in data[table].items():
        if isinstance(record, dict) and record.get(field) == parsed_value:
            print(record_id)

def cmd_count(ydb_path: str, key_path: str, table: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    if table not in data:
        raise SystemExit(f"table not found: {table}")
    print(len(data[table]))

def cmd_drop(ydb_path: str, key_path: str, table: str):
    data, key, _ = load_ydb(ydb_path, key_path)
    if table not in data:
        raise SystemExit(f"table not found: {table}")
    ans = input(f"drop entire table '{table}'? [y/N] ").strip().lower()
    if ans != "y":
        print("aborted")
        return
    del data[table]
    save_ydb(ydb_path, data, key)
    print(f"dropped: {table}")

def cmd_tables(ydb_path: str, key_path: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    for k in data:
        if not k.startswith("_"):
            print(k)

def cmd_exists(ydb_path: str, key_path: str, path: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    try:
        resolve_path(data, path)
        print("true")
    except SystemExit:
        print("false")

def cmd_dump(ydb_path: str, key_path: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    clean = {k: v for k, v in data.items() if not k.startswith("_")}
    print(yaml.dump(clean, default_flow_style=False), end="")

def cmd_snapshot(ydb_path: str, key_path: str):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = Path(ydb_path).stem
    dest = f"{stem}_{ts}.ydb"
    shutil.copy2(ydb_path, dest)
    print(f"snapshot: {dest}")

def cmd_export(ydb_path: str, key_path: str, out_path: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    clean = {k: v for k, v in data.items() if not k.startswith("_")}
    with open(out_path, "w") as f:
        yaml.dump(clean, f, default_flow_style=False)
    print(f"exported: {out_path}")

def cmd_template_list(ydb_path: str, key_path: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    for k in data.get("_templates", {}):
        print(k)

def cmd_template_show(ydb_path: str, key_path: str, name: str):
    data, _, _ = load_ydb(ydb_path, key_path)
    tmpl = data.get("_templates", {}).get(name)
    if tmpl is None:
        raise SystemExit(f"template not found: {name}")
    print(yaml.dump(tmpl, default_flow_style=False), end="")

def resolve_ydb(arg: str) -> str:
    if os.path.exists(arg):
        return arg
    with_ext = arg + ".ydb"
    if os.path.exists(with_ext):
        return with_ext
    raise SystemExit(f"file not found: {arg}")

def find_key(ydb_path: str) -> str | None:
    stem = Path(ydb_path).stem
    key_path = stem + ".key"
    return key_path if os.path.exists(key_path) else None

def main():
    args = sys.argv[1:]
    if not args:
        print("usage: ydb <file.ydb> <command> [args]")
        print("       ydb -c <file.yml|yaml> [-o <out.ydb>]")
        print("       ydb -u <file.ydb> <file.key>")
        print("       ydb -d <file.ydb> <file.key>")
        print("       ydb -g <file.ydb>")
        return

    if args[0] in ("-c", "compile"):
        if len(args) < 2:
            raise SystemExit("usage: ydb -c <file.yml|yaml> [-o <out.ydb>]")
        out = None
        if "-o" in args:
            idx = args.index("-o")
            if idx + 1 >= len(args):
                raise SystemExit("missing value after -o")
            out = args[idx + 1]
        cmd_compile(args[1], out)
        return

    if args[0] in ("-u", "unlock"):
        if len(args) < 3:
            raise SystemExit("usage: ydb -u <file.ydb> <file.key>")
        cmd_unlock(resolve_ydb(args[1]), args[2])
        return

    if args[0] in ("-d", "decompile"):
        if len(args) < 3:
            raise SystemExit("usage: ydb -d <file.ydb> <file.key>")
        cmd_decompile(resolve_ydb(args[1]), args[2])
        return

    if args[0] in ("-g", "genKey"):
        if len(args) < 2:
            raise SystemExit("usage: ydb -g <file.ydb>")
        cmd_genkey(resolve_ydb(args[1]))
        return

    ydb_path = resolve_ydb(args[0])
    key_path = find_key(ydb_path)
    if len(args) < 2:
        raise SystemExit("usage: ydb <file.ydb> <command> [args]")

    cmd = args[1]
    rest = args[2:]

    dispatch = {
        "get":      lambda: cmd_get(ydb_path, key_path, rest[0]),
        "add":      lambda: cmd_add(ydb_path, key_path, rest[0], rest[1], rest[2] if len(rest) > 2 else None),
        "append":   lambda: cmd_append(ydb_path, key_path, rest[0], rest[1]),
        "remove":   lambda: cmd_remove(ydb_path, key_path, rest[0]),
        "set":      lambda: cmd_set(ydb_path, key_path, rest[0], rest[1]),
        "list":     lambda: cmd_list(ydb_path, key_path, rest[0]),
        "find":     lambda: cmd_find(ydb_path, key_path, rest[0], rest[1], rest[2]),
        "count":    lambda: cmd_count(ydb_path, key_path, rest[0]),
        "drop":     lambda: cmd_drop(ydb_path, key_path, rest[0]),
        "tables":   lambda: cmd_tables(ydb_path, key_path),
        "exists":   lambda: cmd_exists(ydb_path, key_path, rest[0]),
        "dump":     lambda: cmd_dump(ydb_path, key_path),
        "snapshot": lambda: cmd_snapshot(ydb_path, key_path),
        "export":   lambda: cmd_export(ydb_path, key_path, rest[0]),
        "template": lambda: (
            cmd_template_list(ydb_path, key_path) if rest[0] == "list" else
            cmd_template_show(ydb_path, key_path, rest[1]) if rest[0] == "show" else
            (_ for _ in ()).throw(SystemExit(f"unknown template subcommand: {rest[0]}"))
        ),
    }

    if cmd not in dispatch:
        raise SystemExit(f"unknown command: {cmd}")

    try:
        dispatch[cmd]()
    except IndexError:
        raise SystemExit(f"missing argument for: {cmd}")

if __name__ == "__main__":
    main()
