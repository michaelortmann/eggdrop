/*
 * tclpython.c -- part of python.mod
 *   contains all tcl functions
 *
 */
/*
 * Copyright (C) 2000 - 2023 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

static int tcl_pysource STDVAR
{
  BADARGS(2, 2, " script");

  putlog(LOG_MISC, "*", "mebbe trying to load %s", argv[1]);
//  PyImport_ImportModule(argv[1]);
}

static tcl_cmds my_tcl_cmds[] = {
  {"pysource",  tcl_pysource},
  {NULL,        NULL}
};
