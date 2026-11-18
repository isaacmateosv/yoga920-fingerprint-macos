import os

# Overridable so the installed root daemon keeps sensor state in a root-only directory.
# Default: the development data dir next to this checkout.
PYTHON_VALIDITY_DATA_DIR = os.environ.get(
    'YOGAFP_VALIDITY_DIR',
    os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..', 'run-data'))) + '/'

def init_data_dir():
    if not os.path.isdir(PYTHON_VALIDITY_DATA_DIR):
        os.mkdir(PYTHON_VALIDITY_DATA_DIR, 0o700)
