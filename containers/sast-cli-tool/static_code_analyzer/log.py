import logging
import logging.handlers
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
            "line": record.lineno
        }
        return json.dumps(log_record)

class Logger:
    def __init__(self, log_file: Optional[str] = None):
        self.logger = logging.getLogger("StaticCodeAnalyzer")
        self.logger.setLevel(logging.DEBUG)

        console_formatter = logging.Formatter("%(levelname)s %(asctime)s [%(module)s:%(funcName)s:%(lineno)d] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        console = logging.StreamHandler()
        console.setFormatter(console_formatter)
        self.logger.addHandler(console)

        if log_file:
            log_path = Path(log_file).resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=10*1024*1024, backupCount=5
            )
            file_handler.setFormatter(JsonFormatter())
            self.logger.addHandler(file_handler)

    def info(self, message: str):
        self.logger.info(f"{bcolors.OKBLUE}{message}{bcolors.ENDC}")

    def warning(self, message: str):
        self.logger.warning(f"{bcolors.YELLOW}{message}{bcolors.ENDC}")

    def error(self, message: str):
        self.logger.error(f"{bcolors.RED}{message}{bcolors.ENDC}")