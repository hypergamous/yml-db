# YDB — YAML Database

A CLI database tool that stores data as encrypted YAML files. Each `.ydb` file is AES-256-GCM encrypted and locked to specific machines via HWID.

---

## Installation

```bash
pip install pyyaml cryptography
```

---

## Concepts

| Term | Description |
|------|-------------|
| `.yaml` | Plain source file you write by hand |
| `.ydb` | Compiled, encrypted database file |
| `.key` | Key file required to unlock and use a `.ydb` |
| HWID | Your machine's unique hardware ID — baked in at compile time |
| path | Dot-notation to a value, e.g. `users.154123441.username` |

---

## Workflow

```
write xample.yaml → ydb -c xample.yaml → xample.ydb + xample.key
                                               ↓
                              ydb xample.ydb get users.154123441.username
```

---

## Commands

### Compile
```bash
ydb -c <file.yaml>
ydb -c <file.yaml> -o <output.ydb>
```
Encrypts a `.yaml` file into a `.ydb` + `.key` pair. The compiling machine's HWID is added to the allowed list automatically.

---

### Unlock
```bash
ydb -u <file.ydb> <file.key>
```
Adds your machine's HWID to the allowed list. Run this on any new machine before using the database.

---

### Decompile
```bash
ydb -d <file.ydb> <file.key>
```
Decrypts and prints the source YAML. Internal headers (`_keyHash`, `_allowedHWID`) are stripped from output.

---

### Regenerate Key
```bash
ydb -g <file.ydb>
```
Generates a new `.key` file. The old key becomes permanently invalid. Prompts for confirmation before proceeding.

---

### Get
```bash
ydb <file.ydb> get <path>
```
```bash
ydb xample.ydb get users.154123441.username
# mycoolgamertag

ydb xample.ydb get users.154123441.permissions
# isAnAdmin: False
# canEditBio: True
# isBanned: False
```

---

### Add
```bash
ydb <file.ydb> add <table> <id> [template]
```
```bash
ydb xample.ydb add users 99999
ydb xample.ydb add users 99999 user
```
Creates a new record. Optionally applies a template defined in `_templates`.

---

### Append
```bash
ydb <file.ydb> append <path> "<key: value>"
```
```bash
ydb xample.ydb append users.154123441 "canFly: True"
ydb xample.ydb append users.154123441.permissions "isMod: True"
```
Merges one or more key-value pairs into an existing dict at the given path.

---

### Set
```bash
ydb <file.ydb> set <path> <value>
```
```bash
ydb xample.ydb set users.154123441.username "newgamertag"
ydb xample.ydb set users.154123441.permissions.isBanned True
```
Overwrites the value at a path.

---

### Remove
```bash
ydb <file.ydb> remove <path>
```
```bash
ydb xample.ydb remove users.154123441.permissions.canFly
ydb xample.ydb remove users.99999
```
Deletes a key or entire record at the given path.

---

### List
```bash
ydb <file.ydb> list <table>
```
```bash
ydb xample.ydb list users
# 154123441
# 99999
```
Lists all record IDs in a table.

---

### Find
```bash
ydb <file.ydb> find <table> <field> <value>
```
```bash
ydb xample.ydb find users username "mycoolgamertag"
# 154123441
```
Returns IDs of all records where `field` equals `value`.

---

### Count
```bash
ydb <file.ydb> count <table>
```
```bash
ydb xample.ydb count users
# 2
```
Returns the number of records in a table.

---

### Drop
```bash
ydb <file.ydb> drop <table>
```
Deletes an entire table. Prompts for confirmation.

---

### Tables
```bash
ydb <file.ydb> tables
```
Lists all table names in the database.

---

### Exists
```bash
ydb <file.ydb> exists <path>
```
```bash
ydb xample.ydb exists users.154123441.username
# true

ydb xample.ydb exists users.999.username
# false
```
Returns `true` or `false`. Useful in scripts.

---

### Dump
```bash
ydb <file.ydb> dump
```
Prints the entire database as plain YAML. Internal headers stripped.

---

### Export
```bash
ydb <file.ydb> export <out.yaml>
```
Writes the decrypted database to a `.yaml` file.

---

### Snapshot
```bash
ydb <file.ydb> snapshot
```
Copies the `.ydb` file to `<name>_<timestamp>.ydb`. No decryption — raw encrypted copy.

---

### Templates

Define templates in your source `.yaml` under `_templates`:

```yaml
_templates:
  user:
    username: ""
    permissions:
      isAnAdmin: False
      canEditBio: True
      isBanned: False
```

```bash
ydb xample.ydb template list
ydb xample.ydb template show user
ydb xample.ydb add users 77777 user
```

---

## Security Model

```
compile time:
  - generates 32-byte random key
  - SHA-512 of key written as line 1 of .ydb
  - compiler HWID added to _allowedHWID
  - blob AES-256-GCM encrypted

operation time:
  - key hash verified against line 1
  - machine HWID checked against _allowedHWID
  - both must pass or operation is rejected

unlock (-u):
  - verifies key hash
  - appends new HWID to _allowedHWID
  - re-encrypts

genkey (-g):
  - new 32-byte key generated
  - old key permanently invalid
  - line 1 replaced with new SHA-512
  - re-encrypted with new key
```

---

## Source YAML Format

```yaml
users:
  154123441:
    username: "mycoolgamertag"
    permissions:
      isAnAdmin: False
      canEditBio: True
      isBanned: False

_templates:
  user:
    username: ""
    permissions:
      isAnAdmin: False
      canEditBio: True
      isBanned: False
```

> Use `.yaml` extension for source files. `.yml` is auto-converted internally but `.yaml` is preferred.

---

## Notes

- Integer keys (e.g. `154123441`) are stored as integers by YAML — use them as-is in paths
- Paths are dot-separated: `table.id.field.subfield`
- All write operations re-encrypt the full file on every save
- `.key` files are raw 32-byte binary — do not edit them
