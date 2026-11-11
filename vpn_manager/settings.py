from pathlib import Path

STATE_VERSION = 4


DEFAULT_STATE_PATH = Path("data/vpn_state.json")


DEFAULT_CONFIG_PATH = Path("data/config.json")


DEFAULT_COMPOSE_FILE = Path("docker-compose.yaml")


DEFAULT_PROFILE_NAME = "default"


DEFAULT_PORT = 443


DEFAULT_API_PORT = 10085


DEFAULT_FINGERPRINT = "chrome"


DEFAULT_FLOW = "xtls-rprx-vision"


DEFAULT_SPIDER_X = "/"


OUTBOUND_DIRECT = "direct"


OUTBOUND_PROXY = "proxy"


OUTBOUND_MODES = {OUTBOUND_DIRECT, OUTBOUND_PROXY}


UPSTREAM_OUTBOUND_TAG = "main_vpn"


XRAY_SERVICE = "xray"


SIZE_UNITS = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}
