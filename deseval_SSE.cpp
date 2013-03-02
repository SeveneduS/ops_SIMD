#include <stdio.h>

#ifdef _M_IA64
#include <sse2mmx.h>
#else
#include <emmintrin.h>
#endif

#include <dvec.h>

// the code was taken from http://www.darkside.com.au/bitslice/ and reworked for SSE2

/*
 * Bitslice implementation of DES.
 *
 * Checks that the plaintext bits p[0] .. p[63]
 * encrypt to the ciphertext bits c[0] .. c[63]
 * given the key bits k[0] .. k[55]
 */

//#include "nonstd_SSE.h"

//#define IS_INLINE
#define IS_INLINE __inline

void 
IS_INLINE sse_s1 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50, x51, x52, x53, x54, x55, x56;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_andnot_si128 (a5, a3);
	x2 = _mm_xor_si128 (x1, a4);
	x3 = _mm_andnot_si128 (a4, a3);
	x4 = _mm_or_si128 (x3, a5);
	x5 = _mm_and_si128 (a6, x4);
	x6 = _mm_xor_si128 (x2, x5);
	x7 = _mm_andnot_si128 (a5, a4);
	x8 = _mm_xor_si128 (a3, a4);
	x9 = _mm_andnot_si128 (x8, a6);
	x10 = _mm_xor_si128 (x7, x9);
	x11 = _mm_or_si128 (a2, x10);
	x12 = _mm_xor_si128 (x6, x11);
	x13 = _mm_xor_si128 (a5, x5);
	x14 = _mm_and_si128 (x13, x8);
	x15 = _mm_andnot_si128 (a4, a5);
	x16 = _mm_xor_si128 (x3, x14);
	x17 = _mm_or_si128 (a6, x16);
	x18 = _mm_xor_si128 (x15, x17);
	x19 = _mm_or_si128 (a2, x18);
	x20 = _mm_xor_si128 (x14, x19);
	x21 = _mm_and_si128 (a1, x20);
	x22 = _mm_xor_si128 (x12, _mm_andnot_si128 (x21, get_mask128()));
	out2 = _mm_xor_si128 (out2, x22);
	x23 = _mm_or_si128 (x1, x5);
	x24 = _mm_xor_si128 (x23, x8);
	x25 = _mm_andnot_si128 (x2, x18);
	x26 = _mm_andnot_si128 (x25, a2);
	x27 = _mm_xor_si128 (x24, x26);
	x28 = _mm_or_si128 (x6, x7);
	x29 = _mm_xor_si128 (x28, x25);
	x30 = _mm_xor_si128 (x9, x24);
	x31 = _mm_andnot_si128 (x30, x18);
	x32 = _mm_and_si128 (a2, x31);
	x33 = _mm_xor_si128 (x29, x32);
	x34 = _mm_and_si128 (a1, x33);
	x35 = _mm_xor_si128 (x27, x34);
	out4 = _mm_xor_si128 (out4, x35);
	x36 = _mm_and_si128 (a3, x28);
	x37 = _mm_andnot_si128 (x36, x18);
	x38 = _mm_or_si128 (a2, x3);
	x39 = _mm_xor_si128 (x37, x38);
	x40 = _mm_or_si128 (a3, x31);
	x41 = _mm_andnot_si128 (x37, x24);
	x42 = _mm_or_si128 (x41, x3);
	x43 = _mm_andnot_si128 (a2, x42);
	x44 = _mm_xor_si128 (x40, x43);
	x45 = _mm_andnot_si128 (x44, a1);
	x46 = _mm_xor_si128 (x39, _mm_andnot_si128 (x45, get_mask128()));
	out1 = _mm_xor_si128 (out1, x46);
	x47 = _mm_andnot_si128 (x9, x33);
	x48 = _mm_xor_si128 (x47, x39);
	x49 = _mm_xor_si128 (x4, x36);
	x50 = _mm_andnot_si128 (x5, x49);
	x51 = _mm_or_si128 (x42, x18);
	x52 = _mm_xor_si128 (x51, a5);
	x53 = _mm_andnot_si128 (x52, a2);
	x54 = _mm_xor_si128 (x50, x53);
	x55 = _mm_or_si128 (a1, x54);
	x56 = _mm_xor_si128 (x48,  _mm_andnot_si128 (x55, get_mask128()));	
	out3 = _mm_xor_si128 (out3, x56);
}

void 
IS_INLINE sse_s2 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_xor_si128 (a1, a6);
	x2 = _mm_xor_si128 (x1, a5);
	x3 = _mm_and_si128 (a6, a5);
	x4 = _mm_andnot_si128 (x3, a1);
	x5 = _mm_andnot_si128 (x4, a2);
	x6 = _mm_xor_si128 (x2, x5);
	x7 = _mm_or_si128 (x3, x5);
	x8 = _mm_andnot_si128 (x1, x7);
	x9 = _mm_or_si128 (a3, x8);
	x10 = _mm_xor_si128 (x6, x9);
	x11 = _mm_andnot_si128 (x4, a5);
	x12 = _mm_or_si128 (x11, a2);
	x13 = _mm_and_si128 (a4, x12);
	x14 = _mm_xor_si128 (x10, _mm_andnot_si128 (x13, get_mask128()));
	out1 = _mm_xor_si128 (out1, x14);
	x15 = _mm_xor_si128 (x4, x14);
	x16 = _mm_andnot_si128 (a2, x15);
	x17 = _mm_xor_si128 (x2, x16);
	x18 = _mm_andnot_si128 (x4, a6);
	x19 = _mm_xor_si128 (x6, x11);
	x20 = _mm_and_si128 (a2, x19);
	x21 = _mm_xor_si128 (x18, x20);
	x22 = _mm_and_si128 (a3, x21);
	x23 = _mm_xor_si128 (x17, x22);
	x24 = _mm_xor_si128 (a5, a2);
	x25 = _mm_andnot_si128 (x8, x24);
	x26 = _mm_or_si128 (x6, a1);
	x27 = _mm_xor_si128 (x26, a2);
	x28 = _mm_andnot_si128 (x27, a3);
	x29 = _mm_xor_si128 (x25, x28);
	x30 = _mm_or_si128 (a4, x29);
	x31 = _mm_xor_si128 (x23, x30);
	out3 = _mm_xor_si128 (out3, x31);
	x32 = _mm_or_si128 (x18, x25);
	x33 = _mm_xor_si128 (x32, x10);
	x34 = _mm_or_si128 (x27, x20);
	x35 = _mm_and_si128 (a3, x34);
	x36 = _mm_xor_si128 (x33, x35);
	x37 = _mm_and_si128 (x24, x34);
	x38 = _mm_andnot_si128 (x37, x12);
	x39 = _mm_or_si128 (a4, x38);
	x40 = _mm_xor_si128 (x36, _mm_andnot_si128 (x39, get_mask128()));
	out4 = _mm_xor_si128 (out4, x40);
	x41 = _mm_xor_si128 (a2, x2);
	x42 = _mm_andnot_si128 (x33, x41);
	x43 = _mm_xor_si128 (x42, x29);
	x44 = _mm_andnot_si128 (x43, a3);
	x45 = _mm_xor_si128 (x41, x44);
	x46 = _mm_or_si128 (x3, x20);
	x47 = _mm_and_si128 (a3, x3);
	x48 = _mm_xor_si128 (x46, x47);
	x49 = _mm_andnot_si128 (x48, a4);
	x50 = _mm_xor_si128 (x45, _mm_andnot_si128 (x49, get_mask128()));
	out2 = _mm_xor_si128 (out2, x50);
}


void 
IS_INLINE sse_s3 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50, x51, x52, x53;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_xor_si128 (a2, a3);
	x2 = _mm_xor_si128 (x1, a6);
	x3 = _mm_and_si128 (a2, x2);
	x4 = _mm_or_si128 (a5, x3);
	x5 = _mm_xor_si128 (x2, x4);
	x6 = _mm_xor_si128 (a3, x3);
	x7 = _mm_andnot_si128 (a5, x6);
	x8 = _mm_or_si128 (a1, x7);
	x9 = _mm_xor_si128 (x5, x8);
	x10 = _mm_andnot_si128 (x3, a6);
	x11 = _mm_xor_si128 (x10, a5);
	x12 = _mm_and_si128 (a1, x11);
	x13 = _mm_xor_si128 (a5, x12);
	x14 = _mm_or_si128 (a4, x13);
	x15 = _mm_xor_si128 (x9, x14);
	out4 = _mm_xor_si128 (out4, x15);
	x16 = _mm_and_si128 (a3, a6);
	x17 = _mm_or_si128 (x16, x3);
	x18 = _mm_xor_si128 (x17, a5);
	x19 = _mm_andnot_si128 (x7, x2);
	x20 = _mm_xor_si128 (x19, x16);
	x21 = _mm_or_si128 (a1, x20);
	x22 = _mm_xor_si128 (x18, x21);
	x23 = _mm_or_si128 (a2, x7);
	x24 = _mm_xor_si128 (x23, x4);
	x25 = _mm_or_si128 (x11, x19);
	x26 = _mm_xor_si128 (x25, x17);
	x27 = _mm_or_si128 (a1, x26);
	x28 = _mm_xor_si128 (x24, x27);
	x29 = _mm_andnot_si128 (x28, a4);
	x30 = _mm_xor_si128 (x22, _mm_andnot_si128 (x29, get_mask128()));
	out3 = _mm_xor_si128 (out3, x30);
	x31 = _mm_and_si128 (a3, a5);
	x32 = _mm_xor_si128 (x31, x2);
	x33 = _mm_andnot_si128 (a3, x7);
	x34 = _mm_or_si128 (a1, x33);
	x35 = _mm_xor_si128 (x32, x34);
	x36 = _mm_or_si128 (x10, x26);
	x37 = _mm_xor_si128 (a6, x17);
	x38 = _mm_andnot_si128 (x5, x37);
	x39 = _mm_and_si128 (a1, x38);
	x40 = _mm_xor_si128 (x36, x39);
	x41 = _mm_and_si128 (a4, x40);
	x42 = _mm_xor_si128 (x35, x41);
	out2 = _mm_xor_si128 (out2, x42);
	x43 = _mm_or_si128 (a2, x19);
	x44 = _mm_xor_si128 (x43, x18);
	x45 = _mm_and_si128 (a6, x15);
	x46 = _mm_xor_si128 (x45, x6);
	x47 = _mm_andnot_si128 (a1, x46);
	x48 = _mm_xor_si128 (x44, x47);
	x49 = _mm_andnot_si128 (x23, x42);
	x50 = _mm_or_si128 (a1, x49);
	x51 = _mm_xor_si128 (x47, x50);
	x52 = _mm_and_si128 (a4, x51);
	x53 = _mm_xor_si128 (x48, _mm_andnot_si128 (x52, get_mask128()));
	out1 = _mm_xor_si128 (out1, x53);
}


void 
IS_INLINE sse_s4 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_or_si128 (a1, a3);
	x2 = _mm_and_si128 (a5, x1);
	x3 = _mm_xor_si128 (a1, x2);
	x4 = _mm_or_si128 (a2, a3);
	x5 = _mm_xor_si128 (x3, x4);
	x6 = _mm_andnot_si128 (a1, a3);
	x7 = _mm_or_si128 (x6, x3);
	x8 = _mm_and_si128 (a2, x7);
	x9 = _mm_xor_si128 (a5, x8);
	x10 = _mm_and_si128 (a4, x9);
	x11 = _mm_xor_si128 (x5, x10);
	x12 = _mm_xor_si128 (a3, x2);
	x13 = _mm_andnot_si128 (x12, a2);
	x14 = _mm_xor_si128 (x7, x13);
	x15 = _mm_or_si128 (x12, x3);
	x16 = _mm_xor_si128 (a3, a5);
	x17 = _mm_andnot_si128 (a2, x16);
	x18 = _mm_xor_si128 (x15, x17);
	x19 = _mm_or_si128 (a4, x18);
	x20 = _mm_xor_si128 (x14, x19);
	x21 = _mm_or_si128 (a6, x20);
	x22 = _mm_xor_si128 (x11, x21);
	out1 = _mm_xor_si128 (out1, x22);
	x23 = _mm_and_si128 (a6, x20);
	x24 = _mm_xor_si128 (x23, _mm_andnot_si128 (x11, get_mask128()));
	out2 = _mm_xor_si128 (out2, x24);
	x25 = _mm_and_si128 (a2, x9);
	x26 = _mm_xor_si128 (x25, x15);
	x27 = _mm_xor_si128 (a3, x8);
	x28 = _mm_xor_si128 (x27, x17);
	x29 = _mm_andnot_si128 (x28, a4);
	x30 = _mm_xor_si128 (x26, x29);
	x31 = _mm_xor_si128 (x11, x30);
	x32 = _mm_andnot_si128 (x31, a2);
	x33 = _mm_xor_si128 (x22, x32);
	x34 = _mm_andnot_si128 (a4, x31);
	x35 = _mm_xor_si128 (x33, x34);
	x36 = _mm_or_si128 (a6, x35);
	x37 = _mm_xor_si128 (x30, _mm_andnot_si128 (x36, get_mask128()));
	out3 = _mm_xor_si128 (out3, x37);
	x38 = _mm_xor_si128 (x23, x35);
	x39 = _mm_xor_si128 (x38, x37);
	out4 = _mm_xor_si128 (out4, x39);
}


void 
IS_INLINE sse_s5 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50, x51, x52, x53, x54, x55, x56;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_andnot_si128 (a4, a3);
	x2 = _mm_xor_si128 (x1, a1);
	x3 = _mm_andnot_si128 (a3, a1);
	x4 = _mm_or_si128 (a6, x3);
	x5 = _mm_xor_si128 (x2, x4);
	x6 = _mm_xor_si128 (a4, a1);
	x7 = _mm_or_si128 (x6, x1);
	x8 = _mm_andnot_si128 (a6, x7);
	x9 = _mm_xor_si128 (a3, x8);
	x10 = _mm_or_si128 (a5, x9);
	x11 = _mm_xor_si128 (x5, x10);
	x12 = _mm_and_si128 (a3, x7);
	x13 = _mm_xor_si128 (x12, a4);
	x14 = _mm_andnot_si128 (x3, x13);
	x15 = _mm_xor_si128 (a4, x3);
	x16 = _mm_or_si128 (a6, x15);
	x17 = _mm_xor_si128 (x14, x16);
	x18 = _mm_or_si128 (a5, x17);
	x19 = _mm_xor_si128 (x13, x18);
	x20 = _mm_andnot_si128 (a2, x19);
	x21 = _mm_xor_si128 (x11, x20);
	out4 = _mm_xor_si128 (out4, x21);
	x22 = _mm_and_si128 (a4, x4);
	x23 = _mm_xor_si128 (x22, x17);
	x24 = _mm_xor_si128 (a1, x9);
	x25 = _mm_and_si128 (x2, x24);
	x26 = _mm_andnot_si128 (x25, a5);
	x27 = _mm_xor_si128 (x23, x26);
	x28 = _mm_or_si128 (a4, x24);
	x29 = _mm_andnot_si128 (a2, x28);
	x30 = _mm_xor_si128 (x27, x29);
	out2 = _mm_xor_si128 (out2, x30);
	x31 = _mm_and_si128 (x17, x5);
	x32 = _mm_andnot_si128 (x31, x7);
	x33 = _mm_andnot_si128 (a4, x8);
	x34 = _mm_xor_si128 (x33, a3);
	x35 = _mm_and_si128 (a5, x34);
	x36 = _mm_xor_si128 (x32, x35);
	x37 = _mm_or_si128 (x13, x16);
	x38 = _mm_xor_si128 (x9, x31);
	x39 = _mm_or_si128 (a5, x38);
	x40 = _mm_xor_si128 (x37, x39);
	x41 = _mm_or_si128 (a2, x40);
	x42 = _mm_xor_si128 (x36, _mm_andnot_si128 (x41, get_mask128()));
	out3 = _mm_xor_si128 (out3, x42);
	x43 = _mm_andnot_si128 (x32, x19);
	x44 = _mm_xor_si128 (x43, x24);
	x45 = _mm_or_si128 (x27, x43);
	x46 = _mm_xor_si128 (x45, x6);
	x47 = _mm_andnot_si128 (x46, a5);
	x48 = _mm_xor_si128 (x44, x47);
	x49 = _mm_and_si128 (x6, x38);
	x50 = _mm_xor_si128 (x49, x34);
	x51 = _mm_xor_si128 (x21, x38);
	x52 = _mm_andnot_si128 (x51, x28);
	x53 = _mm_and_si128 (a5, x52);
	x54 = _mm_xor_si128 (x50, x53);
	x55 = _mm_or_si128 (a2, x54);
	x56 = _mm_xor_si128 (x48, x55);
	out1 = _mm_xor_si128 (out1, x56);
}


void 
IS_INLINE sse_s6 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50, x51, x52, x53;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_xor_si128 (a5, a1);
	x2 = _mm_xor_si128 (x1, a6);
	x3 = _mm_and_si128 (a1, a6);
	x4 = _mm_andnot_si128 (a5, x3);
	x5 = _mm_andnot_si128 (x4, a4);
	x6 = _mm_xor_si128 (x2, x5);
	x7 = _mm_xor_si128 (a6, x3);
	x8 = _mm_or_si128 (x4, x7);
	x9 = _mm_andnot_si128 (a4, x8);
	x10 = _mm_xor_si128 (x7, x9);
	x11 = _mm_and_si128 (a2, x10);
	x12 = _mm_xor_si128 (x6, x11);
	x13 = _mm_or_si128 (a6, x6);
	x14 = _mm_andnot_si128 (a5, x13);
	x15 = _mm_or_si128 (x4, x10);
	x16 = _mm_andnot_si128 (x15, a2);
	x17 = _mm_xor_si128 (x14, x16);
	x18 = _mm_andnot_si128 (a3, x17);
	x19 = _mm_xor_si128 (x12, _mm_andnot_si128 (x18, get_mask128()));
	out1 = _mm_xor_si128 (out1, x19);
	x20 = _mm_andnot_si128 (x1, x19);
	x21 = _mm_xor_si128 (x20, x15);
	x22 = _mm_andnot_si128 (x21, a6);
	x23 = _mm_xor_si128 (x22, x6);
	x24 = _mm_andnot_si128 (x23, a2);
	x25 = _mm_xor_si128 (x21, x24);
	x26 = _mm_or_si128 (a5, a6);
	x27 = _mm_andnot_si128 (x1, x26);
	x28 = _mm_andnot_si128 (x24, a2);
	x29 = _mm_xor_si128 (x27, x28);
	x30 = _mm_andnot_si128 (x29, a3);
	x31 = _mm_xor_si128 (x25, _mm_andnot_si128 (x30, get_mask128()));
	out4 = _mm_xor_si128 (out4, x31);
	x32 = _mm_xor_si128 (x3, x6);
	x33 = _mm_andnot_si128 (x10, x32);
	x34 = _mm_xor_si128 (a6, x25);
	x35 = _mm_andnot_si128 (x34, a5);
	x36 = _mm_andnot_si128 (x35, a2);
	x37 = _mm_xor_si128 (x33, x36);
	x38 = _mm_andnot_si128 (a5, x21);
	x39 = _mm_or_si128 (a3, x38);
	x40 = _mm_xor_si128 (x37, _mm_andnot_si128 (x39, get_mask128()));
	out3 = _mm_xor_si128 (out3, x40);
	x41 = _mm_or_si128 (x35, x2);
	x42 = _mm_and_si128 (a5, x7);
	x43 = _mm_andnot_si128 (x42, a4);
	x44 = _mm_or_si128 (a2, x43);
	x45 = _mm_xor_si128 (x41, x44);
	x46 = _mm_or_si128 (x23, x35);
	x47 = _mm_xor_si128 (x46, x5);
	x48 = _mm_and_si128 (x26, x33);
	x49 = _mm_xor_si128 (x48, x2);
	x50 = _mm_and_si128 (a2, x49);
	x51 = _mm_xor_si128 (x47, x50);
	x52 = _mm_andnot_si128 (x51, a3);
	x53 = _mm_xor_si128 (x45, _mm_andnot_si128 (x52, get_mask128()));
	out2 = _mm_xor_si128 (out2, x53);
}


void 
IS_INLINE sse_s7 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50, x51;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_and_si128 (a2, a4);
	x2 = _mm_xor_si128 (x1, a5);
	x3 = _mm_and_si128 (a4, x2);
	x4 = _mm_xor_si128 (x3, a2);
	x5 = _mm_andnot_si128 (x4, a3);
	x6 = _mm_xor_si128 (x2, x5);
	x7 = _mm_xor_si128 (a3, x5);
	x8 = _mm_andnot_si128 (x7, a6);
	x9 = _mm_xor_si128 (x6, x8);
	x10 = _mm_or_si128 (a2, a4);
	x11 = _mm_or_si128 (x10, a5);
	x12 = _mm_andnot_si128 (a2, a5);
	x13 = _mm_or_si128 (a3, x12);
	x14 = _mm_xor_si128 (x11, x13);
	x15 = _mm_xor_si128 (x3, x6);
	x16 = _mm_or_si128 (a6, x15);
	x17 = _mm_xor_si128 (x14, x16);
	x18 = _mm_and_si128 (a1, x17);
	x19 = _mm_xor_si128 (x9, x18);
	out1 = _mm_xor_si128 (out1, x19);
	x20 = _mm_andnot_si128 (a3, a4);
	x21 = _mm_andnot_si128 (x20, a2);
	x22 = _mm_and_si128 (a6, x21);
	x23 = _mm_xor_si128 (x9, x22);
	x24 = _mm_xor_si128 (a4, x4);
	x25 = _mm_or_si128 (a3, x3);
	x26 = _mm_xor_si128 (x24, x25);
	x27 = _mm_xor_si128 (a3, x3);
	x28 = _mm_and_si128 (x27, a2);
	x29 = _mm_andnot_si128 (x28, a6);
	x30 = _mm_xor_si128 (x26, x29);
	x31 = _mm_or_si128 (a1, x30);
	x32 = _mm_xor_si128 (x23, _mm_andnot_si128 (x31, get_mask128()));
	out2 = _mm_xor_si128 (out2, x32);
	x33 = _mm_xor_si128 (x7, x30);
	x34 = _mm_or_si128 (a2, x24);
	x35 = _mm_xor_si128 (x34, x19);
	x36 = _mm_andnot_si128 (a6, x35);
	x37 = _mm_xor_si128 (x33, x36);
	x38 = _mm_andnot_si128 (a3, x26);
	x39 = _mm_or_si128 (x38, x30);
	x40 = _mm_andnot_si128 (a1, x39);
	x41 = _mm_xor_si128 (x37, x40);
	out3 = _mm_xor_si128 (out3, x41);
	x42 = _mm_or_si128 (a5, x20);
	x43 = _mm_xor_si128 (x42, x33);
	x44 = _mm_xor_si128 (a2, x15);
	x45 = _mm_andnot_si128 (x44, x24);
	x46 = _mm_and_si128 (a6, x45);
	x47 = _mm_xor_si128 (x43, x46);
	x48 = _mm_and_si128 (a3, x22);
	x49 = _mm_xor_si128 (x48, x46);
	x50 = _mm_or_si128 (a1, x49);
	x51 = _mm_xor_si128 (x47, x50);
	out4 = _mm_xor_si128 (out4, x51);
}


void 
IS_INLINE sse_s8 (
	__m128i	a1_1,
	__m128i	a1_2,
	__m128i	a2_1,
	__m128i	a2_2,
	__m128i	a3_1,
	__m128i	a3_2,
	__m128i	a4_1,
	__m128i	a4_2,
	__m128i	a5_1,
	__m128i	a5_2,
	__m128i	a6_1,
	__m128i	a6_2,
	__m128i	&out1,
	__m128i	&out2,
	__m128i	&out3,
	__m128i	&out4
) {
	__m128i	x1, x2, x3, x4, x5, x6, x7, x8;
	__m128i	x9, x10, x11, x12, x13, x14, x15, x16;
	__m128i	x17, x18, x19, x20, x21, x22, x23, x24;
	__m128i	x25, x26, x27, x28, x29, x30, x31, x32;
	__m128i	x33, x34, x35, x36, x37, x38, x39, x40;
	__m128i	x41, x42, x43, x44, x45, x46, x47, x48;
	__m128i	x49, x50;

	__m128i a1=_mm_xor_si128 (a1_1, a1_2);
	__m128i a2=_mm_xor_si128 (a2_1, a2_2);
	__m128i a3=_mm_xor_si128 (a3_1, a3_2);
	__m128i a4=_mm_xor_si128 (a4_1, a4_2);
	__m128i a5=_mm_xor_si128 (a5_1, a5_2);
	__m128i a6=_mm_xor_si128 (a6_1, a6_2);

	x1 = _mm_xor_si128 (a3, a1);
	x2 = _mm_andnot_si128 (a3, a1);
	x3 = _mm_xor_si128 (x2, a4);
	x4 = _mm_or_si128 (a5, x3);
	x5 = _mm_xor_si128 (x1, x4);
	x6 = _mm_andnot_si128 (a1, x5);
	x7 = _mm_xor_si128 (x6, a3);
	x8 = _mm_andnot_si128 (a5, x7);
	x9 = _mm_xor_si128 (a4, x8);
	x10 = _mm_andnot_si128 (x9, a2);
	x11 = _mm_xor_si128 (x5, x10);
	x12 = _mm_or_si128 (x6, a4);
	x13 = _mm_xor_si128 (x12, x1);
	x14 = _mm_xor_si128 (x13, a5);
	x15 = _mm_andnot_si128 (x14, x3);
	x16 = _mm_xor_si128 (x15, x7);
	x17 = _mm_andnot_si128 (x16, a2);
	x18 = _mm_xor_si128 (x14, x17);
	x19 = _mm_or_si128 (a6, x18);
	x20 = _mm_xor_si128 (x11, _mm_andnot_si128 (x19, get_mask128()));
	out1 = _mm_xor_si128 (out1, x20);
	x21 = _mm_or_si128 (x5, a5);
	x22 = _mm_xor_si128 (x21, x3);
	x23 = _mm_andnot_si128 (a4, x11);
	x24 = _mm_andnot_si128 (x23, a2);
	x25 = _mm_xor_si128 (x22, x24);
	x26 = _mm_and_si128 (a1, x21);
	x27 = _mm_and_si128 (a5, x2);
	x28 = _mm_xor_si128 (x27, x23);
	x29 = _mm_and_si128 (a2, x28);
	x30 = _mm_xor_si128 (x26, x29);
	x31 = _mm_andnot_si128 (a6, x30);
	x32 = _mm_xor_si128 (x25, x31);
	out3 = _mm_xor_si128 (out3, x32);
	x33 = _mm_andnot_si128 (x16, a3);
	x34 = _mm_or_si128 (x9, x33);
	x35 = _mm_or_si128 (a2, x6);
	x36 = _mm_xor_si128 (x34, x35);
	x37 = _mm_andnot_si128 (x14, x2);
	x38 = _mm_or_si128 (x22, x32);
	x39 = _mm_andnot_si128 (x38, a2);
	x40 = _mm_xor_si128 (x37, x39);
	x41 = _mm_or_si128 (a6, x40);
	x42 = _mm_xor_si128 (x36, _mm_andnot_si128 (x41, get_mask128()));
	out2 = _mm_xor_si128 (out2, x42);
	x43 = _mm_andnot_si128 (a5, x1);
	x44 = _mm_or_si128 (x43, a4);
	x45 = _mm_xor_si128 (a3, a5);
	x46 = _mm_xor_si128 (x45, x37);
	x47 = _mm_andnot_si128 (a2, x46);
	x48 = _mm_xor_si128 (x44, x47);
	x49 = _mm_and_si128 (a6, x48);
	x50 = _mm_xor_si128 (x11, _mm_andnot_si128 (x49, get_mask128()));
	out4 = _mm_xor_si128 (out4, x50);
}


void
deseval_SSE (
	 const __m128i 	*p,
	 __m128i 	*c,
	 const __m128i 	*k
	 ) {
	assert (p!=NULL);
	assert (c!=NULL);
	assert (k!=NULL);

  __m128i 	l0 = p[6];
  __m128i 	l1 = p[14];
  __m128i 	l2 = p[22];
  __m128i 	l3 = p[30];
  __m128i 	l4 = p[38];
  __m128i 	l5 = p[46];
  __m128i 	l6 = p[54];
  __m128i 	l7 = p[62];
  __m128i 	l8 = p[4];
  __m128i 	l9 = p[12];
  __m128i 	l10 = p[20];
  __m128i 	l11 = p[28];
  __m128i 	l12 = p[36];
  __m128i 	l13 = p[44];
  __m128i 	l14 = p[52];
  __m128i 	l15 = p[60];
  __m128i 	l16 = p[2];
  __m128i 	l17 = p[10];
  __m128i 	l18 = p[18];
  __m128i 	l19 = p[26];
  __m128i 	l20 = p[34];
  __m128i 	l21 = p[42];
  __m128i 	l22 = p[50];
  __m128i 	l23 = p[58];
  __m128i 	l24 = p[0];
  __m128i 	l25 = p[8];
  __m128i 	l26 = p[16];
  __m128i 	l27 = p[24];
  __m128i 	l28 = p[32];
  __m128i 	l29 = p[40];
  __m128i 	l30 = p[48];
  __m128i 	l31 = p[56];
  __m128i 	r0 = p[7];
  __m128i 	r1 = p[15];
  __m128i 	r2 = p[23];
  __m128i 	r3 = p[31];
  __m128i 	r4 = p[39];
  __m128i 	r5 = p[47];
  __m128i 	r6 = p[55];
  __m128i 	r7 = p[63];
  __m128i 	r8 = p[5];
  __m128i 	r9 = p[13];
  __m128i 	r10 = p[21];
  __m128i 	r11 = p[29];
  __m128i 	r12 = p[37];
  __m128i 	r13 = p[45];
  __m128i 	r14 = p[53];
  __m128i 	r15 = p[61];
  __m128i 	r16 = p[3];
  __m128i 	r17 = p[11];
  __m128i 	r18 = p[19];
  __m128i 	r19 = p[27];
  __m128i 	r20 = p[35];
  __m128i 	r21 = p[43];
  __m128i 	r22 = p[51];
  __m128i 	r23 = p[59];
  __m128i 	r24 = p[1];
  __m128i 	r25 = p[9];
  __m128i 	r26 = p[17];
  __m128i 	r27 = p[25];
  __m128i 	r28 = p[33];
  __m128i 	r29 = p[41];
  __m128i 	r30 = p[49];
  __m128i 	r31 = p[57];

  sse_s1 (r31, k[47], r0, k[11], r1, k[26], r2, k[3], r3, k[13],
	  r4, k[41], l8, l16, l22, l30);
  sse_s2 (r3, k[27], r4, k[6], r5, k[54], r6, k[48], r7, k[39],
	  r8, k[19], l12, l27, l1, l17);
  sse_s3 (r7, k[53], r8, k[25], r9, k[33], r10, k[34], r11, k[17],
	  r12, k[5], l23, l15, l29, l5);
  sse_s4 (r11, k[4], r12, k[55], r13, k[24], r14, k[32], r15, k[40],
	  r16, k[20], l25, l19, l9, l0);
  sse_s5 (r15, k[36], r16, k[31], r17, k[21], r18, k[8], r19, k[23],
	  r20, k[52], l7, l13, l24, l2);
  sse_s6 (r19, k[14], r20, k[29], r21, k[51], r22, k[9], r23, k[35],
	  r24, k[30], l3, l28, l10, l18);
  sse_s7 (r23, k[2], r24, k[37], r25, k[22], r26, k[0], r27, k[42],
	  r28, k[38], l31, l11, l21, l6);
  sse_s8 (r27, k[16], r28, k[43], r29, k[44], r30, k[1], r31, k[7],
	  r0, k[28], l4, l26, l14, l20);
  sse_s1 (l31, k[54], l0, k[18], l1, k[33], l2, k[10], l3, k[20],
	  l4, k[48], r8, r16, r22, r30);
  sse_s2 (l3, k[34], l4, k[13], l5, k[4], l6, k[55], l7, k[46],
	  l8, k[26], r12, r27, r1, r17);
  sse_s3 (l7, k[3], l8, k[32], l9, k[40], l10, k[41], l11, k[24],
	  l12, k[12], r23, r15, r29, r5);
  sse_s4 (l11, k[11], l12, k[5], l13, k[6], l14, k[39], l15, k[47],
	  l16, k[27], r25, r19, r9, r0);
  sse_s5 (l15, k[43], l16, k[38], l17, k[28], l18, k[15], l19, k[30],
	  l20, k[0], r7, r13, r24, r2);
  sse_s6 (l19, k[21], l20, k[36], l21, k[31], l22, k[16], l23, k[42],
	  l24, k[37], r3, r28, r10, r18);
  sse_s7 (l23, k[9], l24, k[44], l25, k[29], l26, k[7], l27, k[49],
	  l28, k[45], r31, r11, r21, r6);
  sse_s8 (l27, k[23], l28, k[50], l29, k[51], l30, k[8], l31, k[14],
	  l0, k[35], r4, r26, r14, r20);
  sse_s1 (r31, k[11], r0, k[32], r1, k[47], r2, k[24], r3, k[34],
	  r4, k[5], l8, l16, l22, l30);
  sse_s2 (r3, k[48], r4, k[27], r5, k[18], r6, k[12], r7, k[3],
	  r8, k[40], l12, l27, l1, l17);
  sse_s3 (r7, k[17], r8, k[46], r9, k[54], r10, k[55], r11, k[13],
	  r12, k[26], l23, l15, l29, l5);
  sse_s4 (r11, k[25], r12, k[19], r13, k[20], r14, k[53], r15, k[4],
	  r16, k[41], l25, l19, l9, l0);
  sse_s5 (r15, k[2], r16, k[52], r17, k[42], r18, k[29], r19, k[44],
	  r20, k[14], l7, l13, l24, l2);
  sse_s6 (r19, k[35], r20, k[50], r21, k[45], r22, k[30], r23, k[1],
	  r24, k[51], l3, l28, l10, l18);
  sse_s7 (r23, k[23], r24, k[31], r25, k[43], r26, k[21], r27, k[8],
	  r28, k[0], l31, l11, l21, l6);
  sse_s8 (r27, k[37], r28, k[9], r29, k[38], r30, k[22], r31, k[28],
	  r0, k[49], l4, l26, l14, l20);
  sse_s1 (l31, k[25], l0, k[46], l1, k[4], l2, k[13], l3, k[48],
	  l4, k[19], r8, r16, r22, r30);
  sse_s2 (l3, k[5], l4, k[41], l5, k[32], l6, k[26], l7, k[17],
	  l8, k[54], r12, r27, r1, r17);
  sse_s3 (l7, k[6], l8, k[3], l9, k[11], l10, k[12], l11, k[27],
	  l12, k[40], r23, r15, r29, r5);
  sse_s4 (l11, k[39], l12, k[33], l13, k[34], l14, k[10], l15, k[18],
	  l16, k[55], r25, r19, r9, r0);
  sse_s5 (l15, k[16], l16, k[7], l17, k[1], l18, k[43], l19, k[31],
	  l20, k[28], r7, r13, r24, r2);
  sse_s6 (l19, k[49], l20, k[9], l21, k[0], l22, k[44], l23, k[15],
	  l24, k[38], r3, r28, r10, r18);
  sse_s7 (l23, k[37], l24, k[45], l25, k[2], l26, k[35], l27, k[22],
	  l28, k[14], r31, r11, r21, r6);
  sse_s8 (l27, k[51], l28, k[23], l29, k[52], l30, k[36], l31, k[42],
	  l0, k[8], r4, r26, r14, r20);
  sse_s1 (r31, k[39], r0, k[3], r1, k[18], r2, k[27], r3, k[5],
	  r4, k[33], l8, l16, l22, l30);
  sse_s2 (r3, k[19], r4, k[55], r5, k[46], r6, k[40], r7, k[6],
	  r8, k[11], l12, l27, l1, l17);
  sse_s3 (r7, k[20], r8, k[17], r9, k[25], r10, k[26], r11, k[41],
	  r12, k[54], l23, l15, l29, l5);
  sse_s4 (r11, k[53], r12, k[47], r13, k[48], r14, k[24], r15, k[32],
	  r16, k[12], l25, l19, l9, l0);
  sse_s5 (r15, k[30], r16, k[21], r17, k[15], r18, k[2], r19, k[45],
	  r20, k[42], l7, l13, l24, l2);
  sse_s6 (r19, k[8], r20, k[23], r21, k[14], r22, k[31], r23, k[29],
	  r24, k[52], l3, l28, l10, l18);
  sse_s7 (r23, k[51], r24, k[0], r25, k[16], r26, k[49], r27, k[36],
	  r28, k[28], l31, l11, l21, l6);
  sse_s8 (r27, k[38], r28, k[37], r29, k[7], r30, k[50], r31, k[1],
	  r0, k[22], l4, l26, l14, l20);
  sse_s1 (l31, k[53], l0, k[17], l1, k[32], l2, k[41], l3, k[19],
	  l4, k[47], r8, r16, r22, r30);
  sse_s2 (l3, k[33], l4, k[12], l5, k[3], l6, k[54], l7, k[20],
	  l8, k[25], r12, r27, r1, r17);
  sse_s3 (l7, k[34], l8, k[6], l9, k[39], l10, k[40], l11, k[55],
	  l12, k[11], r23, r15, r29, r5);
  sse_s4 (l11, k[10], l12, k[4], l13, k[5], l14, k[13], l15, k[46],
	  l16, k[26], r25, r19, r9, r0);
  sse_s5 (l15, k[44], l16, k[35], l17, k[29], l18, k[16], l19, k[0],
	  l20, k[1], r7, r13, r24, r2);
  sse_s6 (l19, k[22], l20, k[37], l21, k[28], l22, k[45], l23, k[43],
	  l24, k[7], r3, r28, r10, r18);
  sse_s7 (l23, k[38], l24, k[14], l25, k[30], l26, k[8], l27, k[50],
	  l28, k[42], r31, r11, r21, r6);
  sse_s8 (l27, k[52], l28, k[51], l29, k[21], l30, k[9], l31, k[15],
	  l0, k[36], r4, r26, r14, r20);
  sse_s1 (r31, k[10], r0, k[6], r1, k[46], r2, k[55], r3, k[33],
	  r4, k[4], l8, l16, l22, l30);
  sse_s2 (r3, k[47], r4, k[26], r5, k[17], r6, k[11], r7, k[34],
	  r8, k[39], l12, l27, l1, l17);
  sse_s3 (r7, k[48], r8, k[20], r9, k[53], r10, k[54], r11, k[12],
	  r12, k[25], l23, l15, l29, l5);
  sse_s4 (r11, k[24], r12, k[18], r13, k[19], r14, k[27], r15, k[3],
	  r16, k[40], l25, l19, l9, l0);
  sse_s5 (r15, k[31], r16, k[49], r17, k[43], r18, k[30], r19, k[14],
	  r20, k[15], l7, l13, l24, l2);
  sse_s6 (r19, k[36], r20, k[51], r21, k[42], r22, k[0], r23, k[2],
	  r24, k[21], l3, l28, l10, l18);
  sse_s7 (r23, k[52], r24, k[28], r25, k[44], r26, k[22], r27, k[9],
	  r28, k[1], l31, l11, l21, l6);
  sse_s8 (r27, k[7], r28, k[38], r29, k[35], r30, k[23], r31, k[29],
	  r0, k[50], l4, l26, l14, l20);
  sse_s1 (l31, k[24], l0, k[20], l1, k[3], l2, k[12], l3, k[47],
	  l4, k[18], r8, r16, r22, r30);
  sse_s2 (l3, k[4], l4, k[40], l5, k[6], l6, k[25], l7, k[48],
	  l8, k[53], r12, r27, r1, r17);
  sse_s3 (l7, k[5], l8, k[34], l9, k[10], l10, k[11], l11, k[26],
	  l12, k[39], r23, r15, r29, r5);
  sse_s4 (l11, k[13], l12, k[32], l13, k[33], l14, k[41], l15, k[17],
	  l16, k[54], r25, r19, r9, r0);
  sse_s5 (l15, k[45], l16, k[8], l17, k[2], l18, k[44], l19, k[28],
	  l20, k[29], r7, r13, r24, r2);
  sse_s6 (l19, k[50], l20, k[38], l21, k[1], l22, k[14], l23, k[16],
	  l24, k[35], r3, r28, r10, r18);
  sse_s7 (l23, k[7], l24, k[42], l25, k[31], l26, k[36], l27, k[23],
	  l28, k[15], r31, r11, r21, r6);
  sse_s8 (l27, k[21], l28, k[52], l29, k[49], l30, k[37], l31, k[43],
	  l0, k[9], r4, r26, r14, r20);
  sse_s1 (r31, k[6], r0, k[27], r1, k[10], r2, k[19], r3, k[54],
	  r4, k[25], l8, l16, l22, l30);
  sse_s2 (r3, k[11], r4, k[47], r5, k[13], r6, k[32], r7, k[55],
	  r8, k[3], l12, l27, l1, l17);
  sse_s3 (r7, k[12], r8, k[41], r9, k[17], r10, k[18], r11, k[33],
	  r12, k[46], l23, l15, l29, l5);
  sse_s4 (r11, k[20], r12, k[39], r13, k[40], r14, k[48], r15, k[24],
	  r16, k[4], l25, l19, l9, l0);
  sse_s5 (r15, k[52], r16, k[15], r17, k[9], r18, k[51], r19, k[35],
	  r20, k[36], l7, l13, l24, l2);
  sse_s6 (r19, k[2], r20, k[45], r21, k[8], r22, k[21], r23, k[23],
	  r24, k[42], l3, l28, l10, l18);
  sse_s7 (r23, k[14], r24, k[49], r25, k[38], r26, k[43], r27, k[30],
	  r28, k[22], l31, l11, l21, l6);
  sse_s8 (r27, k[28], r28, k[0], r29, k[1], r30, k[44], r31, k[50],
	  r0, k[16], l4, l26, l14, l20);
  sse_s1 (l31, k[20], l0, k[41], l1, k[24], l2, k[33], l3, k[11],
	  l4, k[39], r8, r16, r22, r30);
  sse_s2 (l3, k[25], l4, k[4], l5, k[27], l6, k[46], l7, k[12],
	  l8, k[17], r12, r27, r1, r17);
  sse_s3 (l7, k[26], l8, k[55], l9, k[6], l10, k[32], l11, k[47],
	  l12, k[3], r23, r15, r29, r5);
  sse_s4 (l11, k[34], l12, k[53], l13, k[54], l14, k[5], l15, k[13],
	  l16, k[18], r25, r19, r9, r0);
  sse_s5 (l15, k[7], l16, k[29], l17, k[23], l18, k[38], l19, k[49],
	  l20, k[50], r7, r13, r24, r2);
  sse_s6 (l19, k[16], l20, k[0], l21, k[22], l22, k[35], l23, k[37],
	  l24, k[1], r3, r28, r10, r18);
  sse_s7 (l23, k[28], l24, k[8], l25, k[52], l26, k[2], l27, k[44],
	  l28, k[36], r31, r11, r21, r6);
  sse_s8 (l27, k[42], l28, k[14], l29, k[15], l30, k[31], l31, k[9],
	  l0, k[30], r4, r26, r14, r20);
  sse_s1 (r31, k[34], r0, k[55], r1, k[13], r2, k[47], r3, k[25],
	  r4, k[53], l8, l16, l22, l30);
  sse_s2 (r3, k[39], r4, k[18], r5, k[41], r6, k[3], r7, k[26],
	  r8, k[6], l12, l27, l1, l17);
  sse_s3 (r7, k[40], r8, k[12], r9, k[20], r10, k[46], r11, k[4],
	  r12, k[17], l23, l15, l29, l5);
  sse_s4 (r11, k[48], r12, k[10], r13, k[11], r14, k[19], r15, k[27],
	  r16, k[32], l25, l19, l9, l0);
  sse_s5 (r15, k[21], r16, k[43], r17, k[37], r18, k[52], r19, k[8],
	  r20, k[9], l7, l13, l24, l2);
  sse_s6 (r19, k[30], r20, k[14], r21, k[36], r22, k[49], r23, k[51],
	  r24, k[15], l3, l28, l10, l18);
  sse_s7 (r23, k[42], r24, k[22], r25, k[7], r26, k[16], r27, k[31],
	  r28, k[50], l31, l11, l21, l6);
  sse_s8 (r27, k[1], r28, k[28], r29, k[29], r30, k[45], r31, k[23],
	  r0, k[44], l4, l26, l14, l20);
  sse_s1 (l31, k[48], l0, k[12], l1, k[27], l2, k[4], l3, k[39],
	  l4, k[10], r8, r16, r22, r30);
  sse_s2 (l3, k[53], l4, k[32], l5, k[55], l6, k[17], l7, k[40],
	  l8, k[20], r12, r27, r1, r17);
  sse_s3 (l7, k[54], l8, k[26], l9, k[34], l10, k[3], l11, k[18],
	  l12, k[6], r23, r15, r29, r5);
  sse_s4 (l11, k[5], l12, k[24], l13, k[25], l14, k[33], l15, k[41],
	  l16, k[46], r25, r19, r9, r0);
  sse_s5 (l15, k[35], l16, k[2], l17, k[51], l18, k[7], l19, k[22],
	  l20, k[23], r7, r13, r24, r2);
  sse_s6 (l19, k[44], l20, k[28], l21, k[50], l22, k[8], l23, k[38],
	  l24, k[29], r3, r28, r10, r18);
  sse_s7 (l23, k[1], l24, k[36], l25, k[21], l26, k[30], l27, k[45],
	  l28, k[9], r31, r11, r21, r6);
  sse_s8 (l27, k[15], l28, k[42], l29, k[43], l30, k[0], l31, k[37],
	  l0, k[31], r4, r26, r14, r20);
  sse_s1 (r31, k[5], r0, k[26], r1, k[41], r2, k[18], r3, k[53],
	  r4, k[24], l8, l16, l22, l30);
  sse_s2 (r3, k[10], r4, k[46], r5, k[12], r6, k[6], r7, k[54],
	  r8, k[34], l12, l27, l1, l17);
  sse_s3 (r7, k[11], r8, k[40], r9, k[48], r10, k[17], r11, k[32],
	  r12, k[20], l23, l15, l29, l5);
  sse_s4 (r11, k[19], r12, k[13], r13, k[39], r14, k[47], r15, k[55],
	  r16, k[3], l25, l19, l9, l0);
  sse_s5 (r15, k[49], r16, k[16], r17, k[38], r18, k[21], r19, k[36],
	  r20, k[37], l7, l13, l24, l2);
  sse_s6 (r19, k[31], r20, k[42], r21, k[9], r22, k[22], r23, k[52],
	  r24, k[43], l3, l28, l10, l18);
  sse_s7 (r23, k[15], r24, k[50], r25, k[35], r26, k[44], r27, k[0],
	  r28, k[23], l31, l11, l21, l6);
  sse_s8 (r27, k[29], r28, k[1], r29, k[2], r30, k[14], r31, k[51],
	  r0, k[45], l4, l26, l14, l20);
  sse_s1 (l31, k[19], l0, k[40], l1, k[55], l2, k[32], l3, k[10],
	  l4, k[13], r8, r16, r22, r30);
  sse_s2 (l3, k[24], l4, k[3], l5, k[26], l6, k[20], l7, k[11],
	  l8, k[48], r12, r27, r1, r17);
  sse_s3 (l7, k[25], l8, k[54], l9, k[5], l10, k[6], l11, k[46],
	  l12, k[34], r23, r15, r29, r5);
  sse_s4 (l11, k[33], l12, k[27], l13, k[53], l14, k[4], l15, k[12],
	  l16, k[17], r25, r19, r9, r0);
  sse_s5 (l15, k[8], l16, k[30], l17, k[52], l18, k[35], l19, k[50],
	  l20, k[51], r7, r13, r24, r2);
  sse_s6 (l19, k[45], l20, k[1], l21, k[23], l22, k[36], l23, k[7],
	  l24, k[2], r3, r28, r10, r18);
  sse_s7 (l23, k[29], l24, k[9], l25, k[49], l26, k[31], l27, k[14],
	  l28, k[37], r31, r11, r21, r6);
  sse_s8 (l27, k[43], l28, k[15], l29, k[16], l30, k[28], l31, k[38],
	  l0, k[0], r4, r26, r14, r20);
  sse_s1 (r31, k[33], r0, k[54], r1, k[12], r2, k[46], r3, k[24],
	  r4, k[27], l8, l16, l22, l30);

  c[5]=l8;
  c[3]=l16;
  c[51]=l22;
  c[49]=l30;

  sse_s2 (r3, k[13], r4, k[17], r5, k[40], r6, k[34], r7, k[25],
	  r8, k[5], l12, l27, l1, l17);

  c[37]=l12;
  c[25]=l27;
  c[15]=l1;
  c[11]=l17;

  sse_s3 (r7, k[39], r8, k[11], r9, k[19], r10, k[20], r11, k[3],
	  r12, k[48], l23, l15, l29, l5);

  c[59]=l23;
  c[61]=l15;
  c[41]=l29;
  c[47]=l5;

  sse_s4 (r11, k[47], r12, k[41], r13, k[10], r14, k[18], r15, k[26],
	  r16, k[6], l25, l19, l9, l0);

  c[9]=l25;
  c[27]=l19;
  c[13]=l9;
  c[7]=l0;

  sse_s5 (r15, k[22], r16, k[44], r17, k[7], r18, k[49], r19, k[9],
	  r20, k[38], l7, l13, l24, l2);

  c[63]=l7;
  c[45]=l13;
  c[1]=l24;
  c[23]=l2;

  sse_s6 (r19, k[0], r20, k[15], r21, k[37], r22, k[50], r23, k[21],
	  r24, k[16], l3, l28, l10, l18);

  c[31]=l3;
  c[33]=l28;
  c[21]=l10;
  c[19]=l18;

  sse_s7 (r23, k[43], r24, k[23], r25, k[8], r26, k[45], r27, k[28],
	  r28, k[51], l31, l11, l21, l6);

  c[57]=l31;
  c[29]=l11;
  c[43]=l21;
  c[55]=l6;

  sse_s8 (r27, k[2], r28, k[29], r29, k[30], r30, k[42], r31, k[52],
	  r0, k[14], l4, l26, l14, l20);

  c[39]=l4;
  c[17]=l26;
  c[53]=l14;
  c[35]=l20;

  sse_s1 (l31, k[40], l0, k[4], l1, k[19], l2, k[53], l3, k[6],
	  l4, k[34], r8, r16, r22, r30);

  c[4]=r8;
  c[2]=r16;
  c[50]=r22;
  c[48]=r30;

  sse_s2 (l3, k[20], l4, k[24], l5, k[47], l6, k[41], l7, k[32],
	  l8, k[12], r12, r27, r1, r17);

  c[36]=r12;
  c[24]=r27;
  c[14]=r1;
  c[10]=r17;

  sse_s3 (l7, k[46], l8, k[18], l9, k[26], l10, k[27], l11, k[10],
	  l12, k[55], r23, r15, r29, r5);

  c[58]=r23;
  c[60]=r15;
  c[40]=r29;
  c[46]=r5;

  sse_s4 (l11, k[54], l12, k[48], l13, k[17], l14, k[25], l15, k[33],
	  l16, k[13], r25, r19, r9, r0);

  c[8]=r25;
  c[26]=r19;
  c[12]=r9;
  c[6]=r0;

  sse_s5 (l15, k[29], l16, k[51], l17, k[14], l18, k[1], l19, k[16],
	  l20, k[45], r7, r13, r24, r2);

  c[62]=r7;
  c[44]=r13;
  c[0]=r24;
  c[22]=r2;

  sse_s6 (l19, k[7], l20, k[22], l21, k[44], l22, k[2], l23, k[28],
	  l24, k[23], r3, r28, r10, r18);

  c[30]=r3;
  c[32]=r28;
  c[20]=r10;
  c[18]=r18;

  sse_s7 (l23, k[50], l24, k[30], l25, k[15], l26, k[52], l27, k[35],
	  l28, k[31], r31, r11, r21, r6);

  c[56]=r31;
  c[28]=r11;
  c[42]=r21;
  c[54]=r6;

  sse_s8 (l27, k[9], l28, k[36], l29, k[37], l30, k[49], l31, k[0],
	  l0, k[21], r4, r26, r14, r20);

  c[38]=r4;
  c[16]=r26;
  c[52]=r14;
  c[34]=r20;
}
