import threading

# Shared reentrant lock used by both job_scheduler and enclave_manager_buffer
# to serialize compound read-modify-write operations on job state and queue.json.
job_file_lock = threading.RLock()
