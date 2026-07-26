"""
SAFE EXCEPT — Standardized Error Handling Helper
=================================================
Ganti bare `except: pass` jadi proper error logging.

Usage:
    from safe_except import safe_except

    try:
        # ... risky code
    except Exception:
        safe_except("SSRF Scanner", "Error testing param: {param}", exec_logger)
        continue
"""

from typing import Optional, Any


def safe_except(
    tool_name: str,
    message: str,
    logger=None,
    level: str = "WARNING",
    return_value: Any = None,
) -> Any:
    """
    Standardized error handler for replace bare except: pass.
    
    Args:
        tool_name: Nama tool that error
        message: Error message for log
        logger: exec_logger instance (optional)
        level: Log level (WARNING, ERROR, INFO)
        return_value: Value for di-return
    
    Returns:
        return_value (default: None)
    """
    import sys
    exc_type, exc_value, _ = sys.exc_info()
    
    if exc_type:
        full_msg = f"{message} ({exc_type.__name__}: {str(exc_value)[:200]})"
    else:
        full_msg = message

    if logger:
        try:
            logger.add_log(tool_name, level, full_msg)
        except Exception:
            # Logger juga error — silent fail
            pass
    else:
        print(f"[{level}] {tool_name}: {full_msg}")

    return return_value


def safe_except_silent(tool_name: str, logger=None) -> None:
    """
    Minimal silent error handler — log error tapi gak return apa-apa.
    Used for non-critical errors that need to be known.
    """
    import sys
    exc_type, exc_value, _ = sys.exc_info()
    
    if exc_type and logger:
        try:
            logger.add_log(tool_name, "DEBUG", f"{exc_type.__name__}: {str(exc_value)[:100]}")
        except Exception:
            pass
