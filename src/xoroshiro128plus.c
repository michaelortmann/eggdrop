/*
 * xoroshiro128plus.c
 *
 * Written in 2015-2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)
 *
 * This is xoroshiro128+ 1.0, our best and fastest small-state generator
 * for floating-point numbers. We suggest to use its upper bits for
 * floating-point generation, as it is slightly faster than
 * xoroshiro128**. It passes all tests we are aware of except for the four
 * lower bits, which might fail linearity tests (and just those), so if
 * low linear complexity is not considered an issue (as it is usually the
 * case) it can be used to generate 64-bit outputs, too; moreover, this
 * generator has a very mild Hamming-weight dependency making our test
 * (http://prng.di.unimi.it/hwd.php) fail after 8 TB of output; we believe
 * this slight bias cannot affect any application. If you are concerned,
 * use xoroshiro128** or xoshiro256+.
 *
 * We suggest to use a sign test to extract a random Boolean value, and
 * right shifts to extract subsets of bits.
 *
 * The state must be seeded so that it is not everywhere zero. If you have
 * a 64-bit seed, we suggest to seed a splitmix64 generator and use its
 * output to fill s. 
 *
 * NOTE: the parameters (a=24, b=16, b=37) of this version give slightly
 * better results in our test than the 2016 version (a=55, b=14, c=37).
 */
/*
 * Copyright (C) 1999 - 2018 Eggheads Development Team
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

#include <stdint.h>             /* uint64_t       */
#include <stdio.h>              /* printf()       */
#include <unistd.h>             /* getpid()       */
#include <time.h>               /* time()         */
#include <sys/time.h>           /* gettimeofday() */
#include "main.h"               /* EGG_RAND_MAX   */
#ifdef HAVE_GETRANDOM
#  include <sys/random.h>
#endif

/* http://xoshiro.di.unimi.it/splitmix64.c */

static uint64_t x; /* The state can be seeded with any value. */

static uint64_t splitmix64_next()
{
  uint64_t z = (x += 0x9e3779b97f4a7c15);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
  z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
  return z ^ (z >> 31);
}

/* http://xoshiro.di.unimi.it/xoroshiro128plus.c */

static inline uint64_t rotl(const uint64_t x, int k)
{
  return (x << k) | (x >> (64 - k));
}

static uint64_t s[2];

uint64_t xoroshiro128plus_next(void)
{
  const uint64_t s0 = s[0];
  uint64_t s1 = s[1];
  const uint64_t result = s0 + s1;

  s1 ^= s0;
  s[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16); /* a, b */
  s[1] = rotl(s1, 37);                   /* c    */

  return result;
}

/* 20180728 M.Ortmann */
/*
 * besides getrandom() i checked and commented on the following fallback seeding functions:
 * 1. seed = now % (getpid() + getppid());
 *    ld method, broken, mod operation reduces number space for seed to MAXPID +MAXPID
 * 2. seed = now;
 *    most simple version, not broken, but least random
 * 3. seed = now ^ getpid();
 *    unbroken method, xor instead of mod, getppid was overdoing it, kiss
 * 4. seed = (tp.tv_sec * tp.tv_usec) ^ getpid();
 *    best simple method i can think of, seeds with microseconds ins      tead of seconds only
 */
/*
 * now what we do here is rawly the same as
 * http://www.codegists.com/snippet/swift/xoroshiro128plusswift_drhurdle_swift
 * http://www.codegists.com/code/.net-random-number-generator-algorithm/
 * its nice, when we stick pieces togather and the result matches that of others
 * gives confidence
 */
void init_random()
{
#ifdef HAVE_GETRANDOM
  printf("DEBUG: have getrandom()\n");
  if (getrandom(&x, sizeof(x), 0) != sizeof(x))
    fatal("ERROR: getrandom()\n", 0);
#else
  printf("DEBUG: dont have getrandom()\n");
  struct timeval tp;
  gettimeofday(&tp, NULL);
  x = (tp.tv_sec * tp.tv_usec) ^ getpid();
#endif
  printf("DEBUG: seed = %lx\n", x);

  s[0] = splitmix64_next();
  s[1] = splitmix64_next();

  printf("DEBUG: s[0] = %lx\n", s[0]);
  printf("DEBUG: s[1] = %lx\n", s[1]);
}

/*
 * TODO:
 */
/*
unsigned long randint(int n) {
	return xoroshiro128plus_next() / (EGG_RAND_MAX + 1.0) * n;
}
*/

/*
 * 20180728 M.Ortmann
 * 1. put all other random functions like randint() here?
 * or move this file into the file holding the randint() function?
 * we rly wanna keep all rand functions at one place
 * 2. nur die high bits benutzen? shift right?
 * 3. wir wollen die ganzen ifdef/defines aus eggdrop.h entfernen ?
 * 4. set von benoetigten funktionen ueberlegen/darauf umstellen
 * sowas wie rand_bool(), rand_int()?
 * 5. ggf. zusaetzlich sprng einbauen? getrandom() mit fallback arc4rand()
 * und/oder eigenem chacha oder aes?
 * 6. blowfish module und alle anderen random-stellen pruefen
 * und umstellen/testen/ggf. mit sprng wenn crypto benoetigt wird
 * 7. was ist mit dem in entwicklung befindlichen branch mit pbkdf2 mod,
 * das geht zur zeit eigene wege via openssl ?!
 */

/*
 * from src/main.c:mainloop()
 *
 * initial observation:
 *
 * do we need more randomness?
 * if not, get rid of that call here.
 * does this call here even provide the expected more randomness?
 * i mean, if random() is broken, how good can it be to call it 1 more time.
 * if not, get rid of that call here.
 * if any of those questions is yes, there is a better way
 * we should replace the random() function shich is mapped to different
 * operating system functions for portability reasons in eggdrop.h
 * with a portable builtin alternative.
 * of course we would not code random/crypto outself, but use free and tested
 * solutions like Xoroshiro128+
 * see:
 * https://en.wikipedia.org/wiki/Xoroshiro128%2B
 * this is faster and more random than random()/rand() or any mtwister
 * if seeded correctly (smix...)
 * and replace currently bad seeding
 * TIME modulo (PID + GPID) -> only 128k seeding randomness
 * with srng like getrandom(), which is available unter linux/bsd/solaris/...
 * and nothing else than a modern, easy and secure way of /dev/urandom
 * and if we dont have getrandom(), fallback to time milliseconds instead of
 * seconds and/or replace modulo PID with XOR pid
 * XOR pid is only dangerous combined with time, because it can cancel each
 * other out, but with millisecs, the case is better
 *
 * my first patch was some tiny lines to main.c:
 * improving on seed
 *
 * #ifndef HAVE_GETRANDOM
 *   printf("DEBUG: dont have getrandom()\n");
 *   random();
 * #endif
 */

/*
 * what about scripts/alltools.tcl - proc randstring ?
 * das sollten wir ggf. umbauen, so dass wir eine c funktion fuer random
 * string direkt bereitstellen
 *
 * wir koennte auch getrandom() oder next() durchschleifen in c nach tcl,
 * und dann die tcl rand funktion in tcl bauen... ?!
 */
