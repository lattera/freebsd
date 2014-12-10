/*
 * Copyright (c) 2010 Damien Miller. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <strings.h>

int
timingsafe_memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1, *p2;
	size_t i ;
	int r, c, lt, gt;

	r = 0;
	c = 0;

	p1 = (unsigned char *)s1;
	p2 = (unsigned char *)s2;

	for (i = 0; i < n; i ++) {
		lt = (p1[i] - p2[i]) >> 8;
		gt = (p2[i] - p1[i]) >> 8;

		r |= (lt - gt) & ~c;
		c |= lt | gt;
	}

	return (r);
}
