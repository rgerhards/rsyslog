/* mmsnarewinevtsec.h -- shared definitions for the SNARE Windows Event Security parser
 *
 * Copyright (C) 2025 by Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MMSNAREWINEVTSEC_H
#define MMSNAREWINEVTSEC_H

#define MMSNAREWINEVTSEC_FORMAT_TAG "MSWinEventLog"
#define MMSNAREWINEVTSEC_EXPECTED_WRAPPED_FIELDS 14
#define MMSNAREWINEVTSEC_EXPECTED_PURE_FIELDS (MMSNAREWINEVTSEC_EXPECTED_WRAPPED_FIELDS + 1)

#endif /* MMSNAREWINEVTSEC_H */
