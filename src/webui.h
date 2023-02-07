/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * webui.h
 *
 * Written by Michael Ortmann
 *
 * Copyright (C) 2023 Eggheads Development Team
 */

#ifndef _EGG_WEBUI_H
#define _EGG_WEBUI_H

#ifdef TLS

extern struct dcc_table DCC_WEBUI;

void webui_activity(int, char *, int);
void webui_display(int, char *);

#endif /* TLS */

#endif /* _EGG_WEBUI_H */
