/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CONFIRM_SM_H
#define CONFIRM_SM_H

#include <stdbool.h>

#include "eip712/sim_include/keepkey/board/layout.h"

typedef enum { ButtonRequestType_ButtonRequest_Other = 1 } ButtonRequestType;

#define DEBUG_DISPLAY_VAL(TITLE, VALNAME, SIZE, BYTES) \
  {                                                    \
    char str[SIZE + 1];                                \
    int ctr;                                           \
    for (ctr = 0; ctr < SIZE / 2; ctr++) {             \
      snprintf(&str[2 * ctr], 3, "%02x", BYTES);       \
    }                                                  \
    printf("\n%s\n%s %s\n", TITLE, VALNAME, str);      \
  }

#endif
