#/bin/sh

# change path if needed

nasm -f elf32 avx_linux.asm

/opt/intel/Compiler/11.1/069/bin/ia32/icc ops_SIMD.cpp -DUSE_SSE2 deseval_SSE.cpp avx_linux.o -xSSE2 -lpthread -o ops_sse2
strip ops_sse2
/opt/intel/Compiler/11.1/069/bin/ia32/icc ops_SIMD.cpp -DUSE_AVX deseval_AVX.cpp avx_linux.o -xAVX -lpthread -o ops_avx
strip ops_avx
