#!/usr/bin/env python3

# This file is part of sv-witnesses repository: https://github.com/sosy-lab/sv-witnesses
#
# SPDX-FileCopyrightText: 2020 Dirk Beyer <https://www.sosy-lab.org>
#
# SPDX-License-Identifier: Apache-2.0

import sys

sys.dont_write_bytecode = True  # prevent creation of .pyc files

from witnesslint import linter  # noqa

if __name__ == "__main__":
    sys.exit(linter.main(sys.argv))
