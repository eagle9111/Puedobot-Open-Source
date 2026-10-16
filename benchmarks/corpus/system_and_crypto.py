import os
import pickle
import subprocess
import hashlib
import random
import yaml


def backup(user_path):
    os.system("tar czf /tmp/b.tgz " + user_path)  # EXPECT: command_injection


def list_tmp():
    subprocess.run(["ls", "-l", "/tmp"], check=True)  # SAFE


def clean_cache():
    os.system("rm -rf /tmp/cache")  # SAFE


def load_session(blob):
    return pickle.loads(blob)  # EXPECT: insecure_deserialization


def load_config(text):
    return yaml.load(text)  # EXPECT: insecure_deserialization


def load_config_safe(text):
    return yaml.safe_load(text)  # SAFE


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # EXPECT: weak_crypto


def file_checksum(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()  # SAFE


def reset_token():
    return str(random.random())  # EXPECT: insecure_random
