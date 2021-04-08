/*
 * Copyright (c) 2018-2020 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#include <mesosphere/kern_common.hpp>

#if defined(ATMOSPHERE_BOARD_NINTENDO_NX)
    #include <mesosphere/board/nintendo/nx/kern_k_system_control.hpp>

    namespace ams::kern {
        using ams::kern::board::nintendo::nx::KSystemControl;
    }

#elif defined(ATMOSPHERE_BOARD_RASPBERRY_PI4)
    #include <mesosphere/board/raspberry/pi4/kern_k_system_control.hpp>

    namespace ams::kern {
        using ams::kern::board::raspberry::pi4::KSystemControl;
    }

#else
    #error "Unknown board for KSystemControl"
#endif
