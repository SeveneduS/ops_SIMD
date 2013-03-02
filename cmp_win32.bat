@echo off

ml avx.asm /c 
icl deseval_SSE.cpp /QxSSE2 /Ox /c
icl deseval_AVX.cpp /QxAVX /Ox /c
icl ops_SIMD.cpp /DUSE_AVX deseval_AVX.obj avx.obj /Ox /D_CRT_SECURE_NO_WARNINGS /link /OUT:ops_avx.exe
icl ops_SIMD.cpp /DUSE_SSE2 deseval_SSE.obj avx.obj /Ox /D_CRT_SECURE_NO_WARNINGS /link /OUT:ops_sse2.exe
