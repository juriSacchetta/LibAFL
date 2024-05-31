#include <assert.h>
#include <bzlib.h>
#include <stdio.h>

#define M_BLOCK 1000000

typedef unsigned char uchar;

#define M_BLOCK_OUT (M_BLOCK + 1000000)

uchar outbuf[M_BLOCK_OUT];
uchar zbuf[M_BLOCK + 600 + (M_BLOCK / 100)];
int nOut = M_BLOCK_OUT;

int LLVMFuzzerTestOneInput(uchar *Data, size_t Size)
{
    int nZ = M_BLOCK;
    int r = BZ2_bzBuffToBuffCompress(zbuf, &nZ, Data, Size, 9, 0, 30);
    r = BZ2_bzBuffToBuffDecompress(outbuf, &nOut, zbuf, nZ, 0, 0);

    return 0;
}

int main()
{
    LLVMFuzzerTestOneInput(zbuf, sizeof(zbuf));
    return 0;
}
