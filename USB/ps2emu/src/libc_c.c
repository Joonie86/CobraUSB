#include <string.h>

int strcmp(const char *s1, const char *s2)
{
	while ((*s1 && *s2) && (*s1 == *s2))
	{
		s1++;
		s2++;
	}
	
	return *s1 - *s2;
}

 int memcmp(const void *s1, const void *s2, size_t n)
 {
	 const unsigned char *p1 = s1;
	 const unsigned char *p2 = s2;
	 
	 for (int i = 0; i < n; i++)
	 {
		 if (p1[i] != p2[i])
		 {
			 return (p1[i] < p2[i]) ? -1 : 1;
		 }
	 }
	 
	 return 0;
 }
