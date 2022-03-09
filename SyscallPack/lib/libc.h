#include <windows.h>

int m_memcmp(const void* buf1, const void* buf2, size_t count)
{
    if (!buf1 || !buf2)
    {
        return -1;
    }

    unsigned char* p1 = (unsigned char*)buf1;
    unsigned char* p2 = (unsigned char*)buf2;

    int   rc = 0;

    for (size_t i = 0; i < count; i++)
    {
        if (*p1 < *p2)
        {
            rc = -1;
            break;
        }

        if (*p1 > * p2)
        {
            rc = 1;
            break;
        }

        p1++;
        p2++;
    }

    return rc;
}

int strlenC( const char *s ) 
{
    int n = 0;

    while ( s[n] ) ++n;

    return n;
}

int strcmpC(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}




//https://github.com/rsmudge/CVE-2020-0796-BOF/blob/master/src/libc.c
void mycopy(char * dst, const char * src, int size) {
	int x;
	for (x = 0; x < size; x++) {
		*dst = *src;
		dst++;
		src++;
	}
}

char mylc(char a) {
	if (a >= 'A' && a <= 'Z') {
		return a + 32;
	}
	else {
		return a;
	}
}

BOOL mycmpi(char * a, char * b) {
	while (*a != 0 && *b != 0) {
		if (mylc(*a) != mylc(*b))
			return FALSE;
		a++;
		b++;
	}

	return TRUE;
}
