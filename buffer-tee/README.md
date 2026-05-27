# Buffer TEE Package

This folder is the branch-ready code tree for the always-on Buffer TEE.

Included here:
- `enclave_manager_buffer.py`
- `job_scheduler.py`
- shared runtime files: `P3DX_SDK.py`, `tee_tls.py`, `config.yml`, `lib/config.py`
- placeholder helper code: `Bundle/decryption.py`, `Fetch_data/fetch_data.py`
- branch-local Docker files

Recommended branch root:
- Copy the contents of this folder to the repo root for the `buffer-tee` branch

Default local start:
```powershell
$env:PYTHONPATH="$PWD\\.vendor"
python enclave_manager_buffer.py
```
