import logging
import os

def setup_logging(name: str = "vuln_check") -> logging.Logger:
    """
    Sets up a structured logger for the application.
    """
    logger = logging.getLogger(name)
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler('vuln_check.log')

    # Create formatters and add them to handlers
    # Using a simple format for now, could be enhanced with JSON formatter for structured logging
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger
    if not logger.handlers: # Prevent adding duplicate handlers if setup is called multiple times
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

    return logger

logger = setup_logging()
