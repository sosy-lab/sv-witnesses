<!--
This file is part of sv-witnesses repository: https://github.com/sosy-lab/sv-witnesses

SPDX-FileCopyrightText: 2022 Dirk Beyer <https://www.sosy-lab.org>

SPDX-License-Identifier: Apache-2.0
-->

# Witnesslint Changelog

## Version 1.4

Initial release version. Essentially the version used in SV-COMP 2022 with a small number of changes:
 - Added option `excludeRecentChecks` to disable newly introduced checks, e.g. for linting older witnesses.
 - An overview of the checked witness is printed out after linting.
 - Linter output now contains the used linter version.
 - Some bugfixes.