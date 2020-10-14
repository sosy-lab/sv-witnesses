# This file is part of sv-witnesses repository: https://github.com/sosy-lab/sv-witnesses
#
# SPDX-FileCopyrightText: 2020 Dirk Beyer <https://www.sosy-lab.org>
#
# SPDX-License-Identifier: Apache-2.0

"""
This module contains the logging-related aspects of the linter.
"""

import logging

LOGLEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}


def create_logger(loglevel):
    """Initializes the logger instances that are to be used in the linter."""
    loglevel = LOGLEVELS[loglevel]
    pos_logger = logging.getLogger("with_position")
    if not pos_logger.hasHandlers():
        pos_handler = logging.StreamHandler()
        pos_formatter = logging.Formatter("%(levelname)-8s: line %(line)s: %(message)s")
        pos_handler.setFormatter(pos_formatter)
        pos_logger.addHandler(pos_handler)
    pos_logger.setLevel(loglevel)

    no_pos_logger = logging.getLogger("without_position")
    if not no_pos_logger.hasHandlers():
        no_pos_handler = logging.StreamHandler()
        no_pos_formatter = logging.Formatter("%(levelname)-8s: %(message)s")
        no_pos_handler.setFormatter(no_pos_formatter)
        no_pos_logger.addHandler(no_pos_handler)
    no_pos_logger.setLevel(loglevel)


def log(level, msg, lineno):
    if lineno:
        logging.getLogger("with_position").log(level, msg, extra={"line": lineno})
    else:
        logging.getLogger("without_position").log(level, msg)


class LogCounter:
    def __init__(self, function):
        self.function = function
        self.counter = 0

    def __call__(self, *args, **kwargs):
        self.counter += 1
        self.function(*args, **kwargs)


critical = LogCounter(lambda msg, lineno=None: log(logging.CRITICAL, msg, lineno))

error = LogCounter(lambda msg, lineno=None: log(logging.ERROR, msg, lineno))

warning = LogCounter(lambda msg, lineno=None: log(logging.WARNING, msg, lineno))

info = LogCounter(lambda msg, lineno=None: log(logging.INFO, msg, lineno))

debug = LogCounter(lambda msg, lineno=None: log(logging.DEBUG, msg, lineno))
