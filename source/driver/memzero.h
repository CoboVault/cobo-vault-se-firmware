#ifndef __MEMZERO_H__
#define __MEMZERO_H__

static void memzero(void* const pnt, const size_t len)
{
	memset(pnt, 0, len);
}

#endif
