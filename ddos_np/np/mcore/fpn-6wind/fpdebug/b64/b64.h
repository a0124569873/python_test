#ifndef _B64_H_
#define _B64_H_

char * b64_encode(const char *buffer, uint32_t length);
char * b64_decode(char *input, uint32_t length);

#endif // _B64_H_