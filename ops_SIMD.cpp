// This software may be modified, redistributed, and used for any purpose,
// so long as its origin is acknowledged.

#define USE_AVX
//#define USE_SSE2

//#define DEMO

//#define MAX_THREADS 4

// -- Dennis Yurichev <dennis@conus.info>

#define VERSION "0.3"

#ifdef _WIN32
#include <windows.h>
#elif linux
#include <pthread.h>
#include <unistd.h>
#include <strings.h>
#define _snprintf snprintf
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#define _strdup strdup
#else
#error "something wrong"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <memory.h>
#include <time.h>
#include <assert.h>
#include <signal.h>

//#include <emmintrin.h>
#include <immintrin.h>
#include <dvec.h>

#ifdef _DEBUG
#include <crtdbg.h>
#endif

#include <list>
#include <string>

#ifdef USE_AVX
typedef __m256 SIMD;
#ifdef _WIN32
#define EXE_NAME "ops_avx.exe"
#endif
#ifdef linux
#define EXE_NAME "ops_avx"
#endif
#endif

#ifdef USE_SSE2
typedef __m128i SIMD;
#ifdef _WIN32
#define EXE_NAME "ops_sse2.exe"
#endif
#ifdef linux
#define EXE_NAME "ops_sse2"
#endif
#endif

#define BITS_IN_SIMD (sizeof(SIMD)*8)

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

char * def_first_symbol_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char * def_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$_";

#ifdef USE_SSE2
#include "deseval_SSE.h"
#endif
#ifdef USE_AVX
#include "deseval_AVX.h"
#endif

#define ORA_BUF_SIZE 80

#ifdef _WIN32
CRITICAL_SECTION cs;
#endif
#ifdef linux
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
#endif

bool global_stop=false;

void tlock()
{
#ifdef _WIN32
	EnterCriticalSection(&cs);
#endif
#ifdef linux
	assert (pthread_mutex_lock( &mutex1 )==0);
#endif
};

void tunlock()
{
#ifdef _WIN32
	LeaveCriticalSection(&cs);
#endif
#ifdef linux
	pthread_mutex_unlock( &mutex1 );
#endif
};

static time_t start;

struct hash
{
	int hash[64];
	char *uname;
	char *comment;
	bool processed;
	bool current;
	bool solved;
	char *password;
	struct hash *next;
};

struct t
{
	SIMD DES_CBC_cache[10][64];
	int DES_last_block_cached;
#ifndef DEMO
	char *uname;
	int uname_len;
#endif
	int pass_len; // password len without first char!
	int lowest_block_modified;
	uchar pass_first_char;
	__int64	encrypted;
	struct hash* hashes;
	char *charset;
	int charset_len;
	bool stop;
	// arrays, len=pass_len
	uchar *begin_at_password;
	uchar *last_password_crunched;
};

struct t2info
{
	__int64 passwords_total;
	int threads_total;
	int first_char_total;
	struct hash* hashes;
};

char * seconds_to_readable (int s)
{
	int seconds;
	int minutes;
	int hours;
	int days;
	char buf[16];
	char *outbuf;

	outbuf=(char*)malloc (128);
	outbuf[0]=0;

	seconds=s;
	minutes=hours=days=0;

	while (seconds>=60)
	{
		seconds-=60;
		minutes++;
	};

	while (minutes>=60)
	{
		minutes-=60;
		hours++;
	};

	while (hours>=24)
	{
		hours-=24;
		days++;
	};

	*outbuf=0;

	if (days)
	{
		_snprintf (buf, 16, "%dd", days);
		strcpy (outbuf+strlen (outbuf), buf);
	};

	if (hours)
	{
		_snprintf (buf, 16, "%dh", hours);
		strcpy (outbuf+strlen (outbuf), buf);
	};

	if (minutes)
	{
		_snprintf (buf, 16, "%dm", minutes);
		strcpy (outbuf+strlen (outbuf), buf);
	};

	if (seconds)
	{
		_snprintf (buf, 16, "%ds", seconds);
		strcpy (outbuf+strlen (outbuf), buf);
	}

	if (strlen (buf)==0)
		strcpy (outbuf, "?");

	return outbuf;
};

#ifdef USE_AVX
__m256 __inline get_mask256()
{
	return _mm256_castsi256_ps(_mm256_set1_epi8(0xFF));
};
#endif

int get_bit_in_SIMD (SIMD n, int idx)
{
	assert (idx<BITS_IN_SIMD);
	assert (idx!=-1);

	uchar tmp=*(((uchar*)&n)+(idx>>3));

	return (tmp>>(idx&7))&1;
};

uchar get_byte_in_block_rv (SIMD *p, int j, int idx) // p is array [10][64]
{
	int j_l=j&7;
	int j_h=(j-j_l)/8;
	uchar rt=0;

	assert (j<ORA_BUF_SIZE);
	assert (idx<BITS_IN_SIMD);

	for (int i=0; i<8; i++) // bits in each byte of b
	{
		SIMD *p2=&p[i + (7-j_l)*8 + j_h*64];
		if (get_bit_in_SIMD (*p2, idx)==1)
			rt|=1<<i;
	};

	return rt;
};

#ifdef USE_AVX
#define deseval_SIMD deseval_AVX
#define SIMD_xor _mm256_xor_ps
#endif

#ifdef USE_SSE2
#define deseval_SIMD deseval_SSE
#define SIMD_xor _mm_xor_si128
#endif

void DES_CBC (struct t *th, SIMD blks[10][64], int blks_t, SIMD k[56], SIMD *lastblock, bool cache, int lowest_blk_last_modified)
{
	int beg;

	if (cache && th->DES_last_block_cached != -1 && th->DES_last_block_cached >= lowest_blk_last_modified)
	{
		beg=lowest_blk_last_modified;
	}
	else
		beg=0;

	for (int b=beg; b<blks_t; b++)
	{
		if (b==0)
		{
			if (cache)
			{
				deseval_SIMD (&blks[b][0], &th->DES_CBC_cache[0][0], k); // encrypt 256 blocks per once
				th->DES_last_block_cached=0;
			}
			else
			{
				deseval_SIMD (&blks[b][0], lastblock, k); // encrypt 256 blocks per once
			};
		}
		else
		{
			SIMD tmp_p[64];
			for (int i=0; i<64; i++)
			{
				if (cache)
					tmp_p[i]=SIMD_xor (blks[b][i], th->DES_CBC_cache[b-1][i]);
				else
					tmp_p[i]=SIMD_xor (blks[b][i], lastblock[i]);
			};

			if (cache)
			{
				deseval_SIMD (tmp_p, &th->DES_CBC_cache[b][0], k); // encrypt 256 blocks per once
				th->DES_last_block_cached=b;
			}
			else
				deseval_SIMD (tmp_p, lastblock, k); // encrypt 256 blocks per once
		};

		if ((b+1 == blks_t) && cache==true)
			memcpy (lastblock, &th->DES_CBC_cache[b][0], 64*sizeof(SIMD));
	};
};

#ifdef USE_SSE2
#include "key0..F.h"
#endif

#ifdef USE_AVX
__m256 key0123456789ABCDEF_AVX[56];

void key0123456789ABCDEF_AVX_init()
{
	key0123456789ABCDEF_AVX[0]=get_mask256();
	key0123456789ABCDEF_AVX[1]=get_mask256();
	key0123456789ABCDEF_AVX[2]=get_mask256();
	key0123456789ABCDEF_AVX[3]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[4]=get_mask256();
	key0123456789ABCDEF_AVX[5]=get_mask256();
	key0123456789ABCDEF_AVX[6]=get_mask256();
	key0123456789ABCDEF_AVX[7]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[8]=get_mask256();
	key0123456789ABCDEF_AVX[9]=get_mask256();
	key0123456789ABCDEF_AVX[10]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[11]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[12]=get_mask256();
	key0123456789ABCDEF_AVX[13]=get_mask256();
	key0123456789ABCDEF_AVX[14]=get_mask256();
	key0123456789ABCDEF_AVX[15]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[16]=get_mask256();
	key0123456789ABCDEF_AVX[17]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[18]=get_mask256();
	key0123456789ABCDEF_AVX[19]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[20]=get_mask256();
	key0123456789ABCDEF_AVX[21]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[22]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[23]=get_mask256();
	key0123456789ABCDEF_AVX[24]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[25]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[26]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[27]=get_mask256();
	key0123456789ABCDEF_AVX[28]=get_mask256();
	key0123456789ABCDEF_AVX[29]=get_mask256();
	key0123456789ABCDEF_AVX[30]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[31]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[32]=get_mask256();
	key0123456789ABCDEF_AVX[33]=get_mask256();
	key0123456789ABCDEF_AVX[34]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[35]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[36]=get_mask256();
	key0123456789ABCDEF_AVX[37]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[38]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[39]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[40]=get_mask256();
	key0123456789ABCDEF_AVX[41]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[42]=get_mask256();
	key0123456789ABCDEF_AVX[43]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[44]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[45]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[46]=get_mask256();
	key0123456789ABCDEF_AVX[47]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[48]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[49]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[50]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[51]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[52]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[53]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[54]=_mm256_setzero_ps();
	key0123456789ABCDEF_AVX[55]=_mm256_setzero_ps();
};
#endif

bool search_for_hash (uchar *c, struct hash* hashes, struct hash* & found_hash, int *found_idx)
{
	int SIMD_val_len=sizeof(SIMD);

	for (int idx_h=0; idx_h<SIMD_val_len; idx_h++)
		for (int idx_l=0; idx_l<8; idx_l++)
		{
			struct hash* i=hashes;

			while (i!=NULL)
			{
				if (i->current==true && i->solved==false)
				{
					bool eq=true;

					for (int b=0; (b < 64) && (eq==true); b++)
					{
						uchar* ptr=(uchar*)&c[b*SIMD_val_len];
						if (((ptr[idx_h]>>idx_l)&1) != i->hash[b])
							eq=false;
					};

					if (eq==true)
					{
						*found_idx=(idx_h*8 + idx_l);
						found_hash=i;
						return true;
					};
				};

				i=i->next;
			};
		};

	return false;
};

bool is_there_still_unsolved_hashes_among_current (struct hash* hashes)
{
	struct hash* i=hashes;

	assert (hashes!=NULL);

	while (i!=NULL)
	{
		if (i->current==true)
			if (i->solved==false)
				return true;
		i=i->next;
	};

	return false;
};

bool __inline calc_next_password(uchar *pw, int pass_len, int charset_len, int & lowest_pos)
{
	for (int pos=pass_len-1; pos>=0; pos--)
	{
		pw[pos]++;
		if (pw[pos]==charset_len)
			pw[pos]=0;
		else
		{
			if (lowest_pos>pos) lowest_pos=pos;
			return true;
		};
	};
	return false;
};

// megabuf: 256 bytes of first byte, 256 bytes of 2nd byte ... 256 bytes of 80th byte

void __inline update_high_and_low_watermarks (int & megabuf_changes_low, int & megabuf_changes_high, int megabuf_ch_idx)
{
	if (megabuf_changes_low==-1) megabuf_changes_low=megabuf_ch_idx;
	if (megabuf_changes_high==-1) megabuf_changes_high=megabuf_ch_idx;
	if (megabuf_ch_idx>megabuf_changes_high) megabuf_changes_high=megabuf_ch_idx;
	if (megabuf_ch_idx<megabuf_changes_low) megabuf_changes_low=megabuf_ch_idx;
};

int prepare_next_passwords_to_megabuf(struct t *th, int N, uchar *megabuf, 
	bool & megabuf_contain_uname_and_first_char_of_password, 
	int & megabuf_changes_low, int & megabuf_changes_high, int & lowest_blk_last_modified)
{
	int megabuf_idx, megabuf_ch_idx;
	int lowest_pos=th->pass_len-1;
	int prev_lowest_pos=0;

	if (megabuf_contain_uname_and_first_char_of_password==false)
	{
		for (int i=0; i<N; i++)
		{
#ifdef DEMO
			for (int j=0; j<3; j++)
#else
			for (int j=0; j<th->uname_len; j++)
#endif
			{
				megabuf_ch_idx=(j*2 + 1);
				assert (megabuf_ch_idx<ORA_BUF_SIZE);
				megabuf_idx=megabuf_ch_idx*N + i;
#ifdef DEMO
				megabuf[megabuf_idx]="SYS"[j];
#else
				megabuf[megabuf_idx]=th->uname[j];
#endif

				update_high_and_low_watermarks (megabuf_changes_low, megabuf_changes_high, megabuf_ch_idx);
			};

			megabuf_ch_idx=(
#ifdef DEMO
				3
#else
				th->uname_len
#endif
				*2 + 1);
			assert (megabuf_ch_idx<ORA_BUF_SIZE);
			megabuf_idx=megabuf_ch_idx*N + i;
			megabuf[megabuf_idx]=th->pass_first_char;

			update_high_and_low_watermarks (megabuf_changes_low, megabuf_changes_high, megabuf_ch_idx);
		};

		megabuf_contain_uname_and_first_char_of_password=true;
		lowest_blk_last_modified=0;
	};

	int megabuf_ch_idx_part1=
#ifdef DEMO
		3
#else
		th->uname_len
#endif
		*2 + 1;
	for (int i=0; i<N; i++)
	{
		megabuf_ch_idx=megabuf_ch_idx_part1 + (prev_lowest_pos+1)*2;
		for (int j=prev_lowest_pos; j<th->pass_len; j++)
		{
			//megabuf_ch_idx=megabuf_ch_idx_part1 + (j+1)*2;
			assert (megabuf_ch_idx<ORA_BUF_SIZE);
			megabuf_idx=megabuf_ch_idx*N + i;

			uchar *a1=&megabuf[megabuf_idx];
			char *a2=&th->charset[th->last_password_crunched[j]];

			if (*a1 != *a2)
			{
				*a1=*a2;

				update_high_and_low_watermarks (megabuf_changes_low, megabuf_changes_high, megabuf_ch_idx);

				int megabuf_ch_idx_8=megabuf_ch_idx/8;
				if (lowest_blk_last_modified > megabuf_ch_idx_8) lowest_blk_last_modified = megabuf_ch_idx_8;
			};
			megabuf_ch_idx+=2;
		};

		// set next password
		if (calc_next_password(th->last_password_crunched, th->pass_len, th->charset_len, lowest_pos)==false)
		{
			// no more passwords
			return i;
		};
	};

	prev_lowest_pos=lowest_pos;
	lowest_pos=th->pass_len-1;
	return N;
};

void make_N_oracle_hashes(struct t *th, SIMD blocks[10][64], int des_blocks, SIMD lastblock[64], 
	int pass_len, int lowest_blk_last_modified)
{
	SIMD tmp_key[56];

	if (pass_len==0)
		DES_CBC (th, blocks, des_blocks, 
#ifdef USE_AVX
		key0123456789ABCDEF_AVX, 
#endif
#ifdef USE_SSE2
		key0123456789ABCDEF_SSE,
#endif
		lastblock, false, lowest_blk_last_modified);

	DES_CBC (th, blocks, des_blocks, 
#ifdef USE_AVX
		key0123456789ABCDEF_AVX, 
#endif
#ifdef USE_SSE2
		key0123456789ABCDEF_SSE,
#endif
		lastblock, true, lowest_blk_last_modified);

	for (int i=0; i<8; i++)
		memcpy (&tmp_key[i*7], &lastblock[i*8+1], 7*sizeof (SIMD));

	DES_CBC (th, blocks, des_blocks, tmp_key, lastblock, false, lowest_blk_last_modified);
};

// one DES block: [bit0:32 bytes][bit1:32 bytes][bit2:32 bytes]...[bit63:32 bytes]

void prepare_640_values (uchar *megabuf, uchar *SIMD_blocks, int megabuf_changes_low, int megabuf_changes_high)
{
	for (int DES_blk_n=0; DES_blk_n<10; DES_blk_n++) // DES blk number
		for (int DES_blk_pos=0; DES_blk_pos<64; DES_blk_pos++) // DES blk position
		{
			// seek pos in megabuf

			// each DES block in megabuf takes 64 bit or 8 bytes

			int megabuf_changes_byte_pos = DES_blk_n*8 + (DES_blk_pos>>3);
			assert (megabuf_changes_byte_pos<ORA_BUF_SIZE);
			int megabuf_byte_pos = megabuf_changes_byte_pos*BITS_IN_SIMD;

			if (megabuf_changes_byte_pos<=megabuf_changes_high && megabuf_changes_byte_pos>=megabuf_changes_low)
			{
				int megabuf_bit_pos = DES_blk_pos&7;
				int idx = DES_blk_n*64 + (63-DES_blk_pos);

				ushort *w=(ushort*)(SIMD_blocks + idx*sizeof(SIMD));

				for (int outbyte=0; outbyte<sizeof(SIMD)/2; outbyte++)
				{
					__m128i tt=*(__m128i *)&megabuf[megabuf_byte_pos];

					if (megabuf_bit_pos)
						for (int q=0; q<megabuf_bit_pos; q++)
							tt=_mm_slli_epi16 (tt, 1);
					*w=_mm_movemask_epi8 (tt);

					megabuf_byte_pos+=16;
					w++;
				};
			};
		};
};

#ifdef _WIN32
#define THREAD_RESULT DWORD WINAPI 
#define THREAD1_ARG struct t *th
#endif

#ifdef linux
#define THREAD_RESULT void*
#define THREAD1_ARG void* arg
#endif

THREAD_RESULT thread1 (THREAD1_ARG)
{
#ifdef linux
	struct t *th=(struct t *)arg;
#endif
	SIMD SIMD_blocks[10][64];
	SIMD SIMD_lastblock[64];

	memcpy (th->last_password_crunched, th->begin_at_password, th->pass_len);
#define MEGABUF_SIZE (ORA_BUF_SIZE*BITS_IN_SIMD)

	uchar *megabuf;

#ifdef _WIN32
	megabuf=(uchar*)_aligned_malloc (MEGABUF_SIZE, sizeof(SIMD));
#endif
#ifdef linux
	posix_memalign ((void**)&megabuf, sizeof(SIMD), MEGABUF_SIZE);
#endif

	memset (megabuf, 0, MEGABUF_SIZE);

	assert (th->charset!=NULL);

	bool megabuf_contain_uname_and_first_char_of_password=false;

	th->DES_last_block_cached=-1;

	while (1)
	{
		int lowest_blk_last_modified=9;

		// подготовить 128/256 новых паролей и сделать из них N буферов по 80 байт
		// int prepare_next_passwords_to_megabuf(struct t *th, int N, uchar *megabuf, uchar *uname, int uname_len)

		int megabuf_changes_low=-1;
		int megabuf_changes_high=-1;
		int passwords_generated=0;

		passwords_generated=prepare_next_passwords_to_megabuf (th, BITS_IN_SIMD, megabuf, megabuf_contain_uname_and_first_char_of_password, 
			megabuf_changes_low, megabuf_changes_high, lowest_blk_last_modified);

		//printf ("passwords_generated=%d\n", passwords_generated);
		//printf ("passwords:\n");
		//dump_list_of_strings (passwords);

		// сделать из них N буферов по 80 байт
		//fill_megabuf (megabuf, N, (uchar*)th->uname, th->uname_len, passwords);

		// готовим 640 m128 или m256
		// __m128i blks[10][64]

		prepare_640_values (megabuf, (uchar*)SIMD_blocks, megabuf_changes_low, megabuf_changes_high);

		int bytes_to_encrypt=(
#ifdef DEMO
			3
#else
			th->uname_len 
#endif
			+ 1 + th->pass_len)*2;
		int des_blocks=bytes_to_encrypt>>3;
		if ((bytes_to_encrypt&7)!=0)
			des_blocks++;

		// проворачиваем
		make_N_oracle_hashes(th, SIMD_blocks, des_blocks, SIMD_lastblock, th->pass_len, lowest_blk_last_modified);

		// ищем

		int found_idx;
		struct hash *found_hash;
		bool rr=false;

		rr=search_for_hash ((uchar*)SIMD_lastblock, th->hashes, found_hash, &found_idx);

		if (rr)
		{
			// store password

			tlock();

			found_hash->solved=true;
			found_hash->password=(char*)malloc (th->pass_len+2);
			found_hash->password[0]=th->pass_first_char;
			found_hash->password[th->pass_len+1]=0;

			for (int i=1; i<th->pass_len+2; i++)
			{
				found_hash->password[i]=megabuf[(1 + i*2+ 
#ifdef DEMO
					3
#else
					th->uname_len
#endif
					*2)*BITS_IN_SIMD + found_idx];
			};

			tunlock();
		};

		th->encrypted+=passwords_generated+1;
		//assert (th->progress<=1);

		if (is_there_still_unsolved_hashes_among_current (th->hashes)==false || passwords_generated!=BITS_IN_SIMD || th->stop || global_stop)
		{
#ifdef _WIN32
			_aligned_free (megabuf);
			return 0;
#endif
#ifdef linux
			free (megabuf);
			pthread_exit(NULL);
#endif
		};
	};
};

bool SSE2_supported()
{
	int b[4];
	__cpuid(b,1);
	if (b[3] & (1<<26)) // EDX, bit 26
		return true;
	return false;
};

extern "C" int isAvxSupported();

bool t2enable;
struct t *th;

#ifdef _WIN32
HANDLE *THDL;
DWORD *TID;
#endif
#ifdef linux
pthread_t *threads;
#endif

#ifdef _WIN32
#define THREAD2_ARG struct t2info *t2
#endif
#ifdef linux
#define THREAD2_ARG void* arg
#endif

THREAD_RESULT thread2 (THREAD2_ARG)
{
#ifdef linux
	struct t2info *t2=(struct t2info *)arg;
#endif
	while (t2enable)
	{
		char *s;
		int t;
		int percents;
		double sec_per_;

		tlock();

		__int64 encrypted_total=0;
		for (int i=0; i<t2->threads_total; i++)
		{
			//printf ("th[%d].encrypted = %lld\n", i, th[i].encrypted);
			//printf ("th[%d].pass_first_char=%c\n", i, th[i].pass_first_char);
			encrypted_total = encrypted_total + th[i].encrypted;
		};

		tunlock();

		//printf ("encrypted_total =     %lld\n", encrypted_total);
		//printf ("t2->passwords_total = %lld\n", t2->passwords_total);
		//assert (encrypted_total <= (t2->passwords_total));
		double q=(double)encrypted_total / (double)t2->passwords_total;
		percents=(int)(q*100);
		printf ("overall progress=%3d%%", percents);
		t=time(NULL) - start; // time gone
		if (percents)
		{
			sec_per_=t/q;
			s=seconds_to_readable ( sec_per_ * (1-q) );
			printf (" / time remaining: %s   ", s);
			free (s);
		}
		printf ("\r");

#ifdef _WIN32
		Sleep (1000);
#endif
#ifdef linux
		sleep (1);
#endif
	};

	printf ("\n");

#ifdef _WIN32
	return 0;
#endif
#ifdef linux
	pthread_exit(NULL);
#endif
};

void alloc_all(int threads_total)
{
#ifdef _WIN32
	BOOL b=InitializeCriticalSectionAndSpinCount(&cs, 0x80000400);
	assert (b==TRUE);
#endif

#ifdef _WIN32
	THDL=(HANDLE*)malloc (threads_total*sizeof(HANDLE));
	TID=(DWORD*)malloc (threads_total*sizeof(DWORD));
#endif
#ifdef linux
	threads=(pthread_t*)malloc (threads_total*sizeof (pthread_t));
#endif

#ifdef _WIN32
	th=(struct t*)_aligned_malloc (threads_total*sizeof(struct t), 0x20);
#endif
#ifdef linux
	posix_memalign ((void**)&th, 0x10, threads_total*sizeof(struct t));
#endif
};

void free_all(int threads_total)
{
#ifdef _WIN32
	_aligned_free (th);
	free (TID);
	free (THDL);
	DeleteCriticalSection(&cs);
#endif
#ifdef linux
	free (th);
	free (threads);
#endif

};

#ifdef DEMO
void check(struct hash* hashes, int pass_len, char *first_symbol_charset, char *charset, int threads_total)
#else
void check(struct hash* hashes, char *uname, int pass_len, char *first_symbol_charset, char *charset, int threads_total)
#endif
{
	time_t elapsed;

#ifdef _WIN32
	HANDLE T2HDL;
	DWORD T2ID;
#endif
#ifdef linux
	int rc;
	pthread_t T2;
#endif
	struct t2info t2;
	int charset_len=strlen (charset);
	int first_symbol_charset_len=strlen (first_symbol_charset);

	t2.passwords_total=1;
	for (int i=0; i<pass_len-1; i++)
		t2.passwords_total=t2.passwords_total * charset_len;
	t2.passwords_total=t2.passwords_total * first_symbol_charset_len;

	//printf ("t2.passwords_total = %I64d\n", t2.passwords_total);

	if (global_stop) return;

	{
		struct hash* i=hashes;
		int t=0;

		while (i!=NULL)
		{
			if (i->current==true && i->solved==false)
				t++;
			i=i->next;
		};
#ifdef DEMO
		printf ("username=%s: %d unsolved hash(es) left\n", "SYS", t);
#else
		printf ("username=%s: %d unsolved hash(es) left\n", uname, t);
#endif
	};

	assert (first_symbol_charset!=NULL);
	assert (charset!=NULL);

	alloc_all(threads_total);

	start=time(NULL);

#ifndef DEMO
	assert (uname!=NULL);
	printf ("Checking %d-symbol passwords for username %s\n", pass_len, uname);
#else
	printf ("Checking %d-symbol passwords for username %s\n", pass_len, "SYS");
#endif

	// prepare N threads
	for (int i=0; i<threads_total; i++)
	{
#ifndef DEMO
		th[i].uname=uname;
		th[i].uname_len=strlen(uname);
#endif
		th[i].pass_len=pass_len-1;
		th[i].encrypted=0;
		th[i].hashes=hashes;
		th[i].charset=charset;
		th[i].charset_len=strlen(charset);
		th[i].stop=false;

		th[i].begin_at_password=(uchar*)malloc (pass_len-1);
		th[i].last_password_crunched=(uchar*)malloc (pass_len-1);
	};

	// start T2
	t2enable=true;
	t2.threads_total=threads_total;
	t2.first_char_total=first_symbol_charset_len;
	t2.hashes=hashes;
#ifdef _WIN32
	T2HDL=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread2, (PVOID)&t2, 0, &T2ID);
#endif
#ifdef linux
	rc = pthread_create(&T2, NULL, thread2, (void *)&t2);
	assert (rc==0);
#endif

	for (int passchar=0; passchar<first_symbol_charset_len;)
	{
		// start N threads
		for (int tt=0; (tt<threads_total) && (passchar<first_symbol_charset_len); tt++)
		{
			// modify first password char in each thread
			th[tt].pass_first_char=first_symbol_charset[passchar];
			memset (th[tt].begin_at_password, 0, pass_len-1);

			// start thread
#ifdef _WIN32
			THDL[tt]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread1, (PVOID)&th[tt], 0, &TID[tt]);
			BOOL b=SetThreadPriority (THDL[tt], THREAD_PRIORITY_BELOW_NORMAL);
			assert (b==TRUE);
#endif
#ifdef linux
			rc = pthread_create(&threads[tt], NULL, thread1, (void *)&th[tt]);
			assert (rc==0);
#endif
			passchar++;
		};

		// wait for them
#ifdef _WIN32
		WaitForMultipleObjects(threads_total, THDL, TRUE, INFINITE);
#endif
#ifdef linux
		for (int i=0; i<threads_total; i++)
			pthread_join(threads[i], NULL);
#endif
	};
	// stop T2
	t2enable=false;
#ifdef _WIN32
	WaitForSingleObject (T2HDL, INFINITE);
#endif
#ifdef linux
	pthread_join(T2, NULL);
#endif

	elapsed=(time(NULL)-start);

	if (elapsed > 1)
	{
		__int64 encrypted_total=0;

		char *s=seconds_to_readable (elapsed);
		printf ("time elapsed: %s, ", s);
		free (s);

		for (int i=0; i<threads_total; i++)
			encrypted_total+=th[i].encrypted;

#ifdef _WIN32
		printf ("~ %I64d", encrypted_total / elapsed);
#endif
#ifdef linux
		printf ("~ %lld", encrypted_total / elapsed);
#endif
		printf (" passwords/hashes per second\n");
	};

	{
		struct hash* i=hashes;

		while (i!=NULL)
		{
			if (i->current==true && i->solved==true)
			{
				i->current=false;
				printf ("%s/%s: Found password: %s\n", i->uname, i->comment, i->password);
			};
			i=i->next;
		};
	};

	free_all(threads_total);
	return;
};

void usage()
{
	printf ("Usage:\n"
		"\n"
		"  %s --hashlist=filename.txt\n"
		"    [--min=min_password_length] [--max=max_password_length]\n"
		"    [--first_symbol_charset=characters] [--charset=characters]\n"
		"    [--results=filename.txt]\n"
		"\n"
		"hashlist file format:\n"
		"username:hash:comment_or_SID\n"
		"\n"
		"By default, results are dumped to stdout.\n"
		"This can be changed by setting --results option\n"
		"\n"
		"Default values:\n"
		"  min_password_length=1\n"
		"  max_password_length=8\n"
		"  first_symbol_charset=%s\n"
		"  charset=%s\n"
		"\n",
		EXE_NAME,
		def_first_symbol_charset,
		def_charset);
};

int get_n_of_cores()
{
#ifdef _WIN32
	SYSTEM_INFO sysinfo;
	GetSystemInfo( &sysinfo );

	return sysinfo.dwNumberOfProcessors;
#endif

#ifdef linux
	return sysconf( _SC_NPROCESSORS_ONLN );
#endif
};

void set_byte_in_bool64 (int *p, int j, uchar b)
{
	assert (j<ORA_BUF_SIZE);

	for (int i=0; i<8; i++)
		p[i+j*8]=(b>>i)&1;
};

bool hexstring_to_byte (char* ptr, uchar *out)
{
	char q[3];
	char *endptr;
	uint r;

	q[0]=tolower (ptr[0]);
	q[1]=tolower (ptr[1]);
	q[2]=0;

	if (isxdigit(q[0])==0) return false;
	if (isxdigit(q[1])==0) return false;

	r=strtoul (q, &endptr, 16);

	*out=r&0xFF;

	if (endptr==ptr)
		return false;

	return true;
};

bool read_line (char *buf, int line_n, struct hash* fill)
{
	char* uname;
	char* hash;
	char* comment;
	uint hash_i[8];
	uchar hash_c[8];

	uname=strtok (buf, ":");
	hash=strtok (NULL, ":");
	comment=strtok (NULL, ":");

	comment=strtok (comment, "\n");
	comment=strtok (comment, "\r");

	if (uname==NULL)
	{
		printf ("can't find username at line #%d in file\n", line_n);
		return false;
	};

	if (hash==NULL)
	{
		printf ("can't find hash value at line #%d in file\n", line_n);
		return false;
	};

	if (comment==NULL)
		comment="";

	if (strlen (uname)>20)
	{
		printf ("%s: Username length is limited to 20 symbols\n", uname);
		return false;
	};

	for (int i=0; i<strlen (uname); i++)
		uname[i]=toupper (uname[i]); // linux doesn't have strupr

#ifdef DEMO
	if (strcmp (uname, "SYS")!=0)
	{
		printf ("%s: Only SYS usernames allowed in demo version.\nGet a PRO version to support any username.\n", uname);
		return false;
	};
#endif

	fill->uname=_strdup (uname);

	if (strlen (hash)!=16)
	{
		printf ("%s: hash value must be exactly 16 hexadecimal symbols long.\n", hash);
		return false;
	};

	for (int i=0; i<8; i++)
	{
		uchar tmp;
		bool rt=hexstring_to_byte (hash+i*2, &tmp);

		if (rt==false)
		{
			printf ("%s: Something wrong with hash value.\n", hash);
			return false;
		};

		set_byte_in_bool64 (fill->hash, 7-i, tmp);
	};

	fill->comment=_strdup (comment);
	fill->password=NULL;
	fill->solved=false;
	fill->processed=false;

	return true;
};

struct hash* read_file (char *fname)
{
	FILE *f;
	char buf[1024];
	int line_n=0;

	struct hash* top=NULL;
	struct hash* last=NULL;

	f=fopen (fname, "rt");
	if (f==NULL)
	{
		printf ("Unable to open file %s\n", fname);
		return NULL;
	};

	while (fgets (buf, sizeof (buf), f)!=NULL)
	{
		line_n++;

		if (top==NULL)
		{
			top=(struct hash *)malloc (sizeof (struct hash));
			assert (top!=NULL);
			last=top;
		}
		else
		{
			last->next=(struct hash *)malloc (sizeof (struct hash));
			assert (last->next!=NULL);
			last=last->next;
		};

		if (read_line (buf, line_n, last)==false)
		{
			fclose (f);
			return NULL;
		};

		last->next=NULL;
	};

	fclose (f);

	return top;
};

char* find_unprocessed_uname (struct hash* hashes)
{
	struct hash* i=hashes;

	assert (hashes!=NULL);

	while (i!=NULL)
	{
		if (i->processed==false)
			return i->uname;
		i=i->next;
	};

	return NULL;
};

void check_all_with_uname (struct hash* hashes, char* uname, int pass_min, int pass_max, 
	char *first_symbol_charset, char *charset, int threads)
{
	// mark all entries with uname as "current"

	struct hash* i;

	assert (hashes!=NULL);

	i=hashes;
	while (i!=NULL)
	{
#ifdef DEMO
		if (strcmp ("SYS", uname)==0)
#else
		if (strcmp (i->uname, uname)==0)
#endif
			i->current=true;
		i=i->next;
	};

	for (int pass_len=pass_min; pass_len<=pass_max; pass_len++)
		if (is_there_still_unsolved_hashes_among_current (hashes))
		{
#ifdef DEMO
			check (hashes, pass_len, first_symbol_charset, charset, threads);
#else
			check (hashes, uname, pass_len, first_symbol_charset, charset, threads);
#endif
		};

	// mark all entries with uname as "processed" and "current=false"

	i=hashes;
	while (i!=NULL)
	{
#ifdef DEMO
		if (strcmp ("SYS", uname)==0)
#else
		if (strcmp (i->uname, uname)==0)
#endif
		{
			i->current=false;
			i->processed=true;
		};
		i=i->next;
	};
};

void dump_table(struct hash* hashes, char* a_results)
{
	struct hash* i=hashes;
	FILE* f=NULL;

	if (a_results!=NULL)
	{
		f=fopen (a_results, "wt");
		if (f==NULL)
			printf ("Unable to create file %s\n", a_results);
	};

	assert (hashes!=NULL);

	while (i!=NULL)
	{
		if (f==NULL)
		{
#ifdef DEMO
			printf ("SYS:%s:%s\n", (i->solved==true) ? i->password : "?", i->comment);
#else
			printf ("%s:%s:%s\n", i->uname, (i->solved==true) ? i->password : "?", i->comment);
#endif
		}
		else
		{
#ifdef DEMO
			fprintf (f, "SYS:%s:%s\n", (i->solved==true) ? i->password : "?", i->comment);
#else
			fprintf (f, "%s:%s:%s\n", i->uname, (i->solved==true) ? i->password : "?", i->comment);
#endif
		}
		i=i->next;
	};

	if (f!=NULL)
	{
		fclose (f);
		printf ("Results are dumped to %s\n", a_results);
	};
};

void __cdecl signal_handler (int signo)
{
	if (signo==SIGINT)
	{
		printf ("Ctrl-C detected\n");
		global_stop=true;
	};
};

int main(int argc, char *argv[])
{
	char* a_hashlist=NULL;
	char* a_results=NULL;
	int a_min=1;
	int a_max=8;
	char* a_first_symbol_charset=def_first_symbol_charset;
	char* a_charset=def_charset;

#ifdef _DEBUG
	HANDLE hLogFile;
	hLogFile = CreateFile(L"leaklog.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	_CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_WARN, hLogFile );
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_ERROR, hLogFile );
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_ASSERT, hLogFile );

	// Get current flag
	int tmpFlag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );

	// Turn on leak-checking bit.
	tmpFlag |= _CRTDBG_LEAK_CHECK_DF;

	// Turn off CRT block checking bit.
	tmpFlag &= ~_CRTDBG_CHECK_CRT_DF;

	// Set flag to the new value.
	_CrtSetDbgFlag( tmpFlag );
#endif

	printf ("Oracle passwords (DES) solver %s (%s) -- Dennis Yurichev <dennis@conus.info>\n", VERSION,
#ifdef USE_AVX
		"AVX"
#endif
#ifdef USE_SSE2
		"SSE2"
#endif
		);
	printf ("Compiled @ " __DATE__ " " __TIME__ "\n");

#ifdef DEMO
	printf ("Demo version, supporting only SYS usernames.\n");
#endif

	if (SSE2_supported()==false)
	{
		printf ("Error: SSE2 instruction set is not supported on this CPU.\n");
		return 0;
	};

#ifdef USE_SSE2
	if (isAvxSupported()!=0)
	{
		printf ("AVX instruction set is supported on this CPU.\n");
		printf ("Use ops_avx.exe, it is working faster than on SSE2 set.\n");
	};
#endif

#ifdef USE_AVX
	if (isAvxSupported()==0)
	{
		printf ("Error: AVX instruction set is not supported on this CPU.\n");
		printf ("Use ops_sse2.exe instead of ops_avx.exe\n");
		return 0;
	}
	key0123456789ABCDEF_AVX_init();
#endif

	int cores=get_n_of_cores();

	for (int i=1; i<argc; i++)
	{
		assert (argv[i]!=NULL);

		if (_strnicmp (argv[i], "--hashlist=", strlen ("--hashlist="))==0)
			a_hashlist=argv[i] + strlen ("--hashlist=");
		else
			if (_strnicmp (argv[i], "--results=", strlen ("--results="))==0)
				a_results=argv[i] + strlen ("--results=");
			else
				if (_strnicmp (argv[i], "--min=", strlen ("--min="))==0)
				{
					if (sscanf (argv[i] + strlen ("--min="), "%d", &a_min)!=1)
					{
						printf ("Unrecognized option [%s]\n", argv[i]);
						return 0;
					};
				}
				else
					if (_strnicmp (argv[i], "--max=", strlen ("--max="))==0)
					{
						if (sscanf (argv[i] + strlen ("--max="), "%d", &a_max)!=1)
						{
							printf ("Unrecognized option [%s]\n", argv[i]);
							return 0;
						};
					}
					else
						if (_strnicmp (argv[i], "--first_symbol_charset=", strlen ("--first_symbol_charset="))==0)
							a_first_symbol_charset=argv[i] + strlen ("--first_symbol_charset="); // TODO: expand_charset
						else
							if (_strnicmp (argv[i], "--charset=", strlen ("--charset="))==0)
								a_charset=argv[i] + strlen ("--charset="); // TODO: expand_charset
							else
							{
								printf ("Unrecognized option [%s]\n", argv[i]);
								return 0;
							};
	};

	if (a_min>a_max)
	{
		printf ("--min value must be less than or equal to --max value\n");
		return 0;
	};

	if (a_hashlist==NULL)
	{
		usage();
		return 0;
	}
	else
	{
		struct hash* hashes;
		char* uname;

#ifdef linux
		__sighandler_t r;
#else
		void* r;
#endif

		hashes=read_file (a_hashlist);
		if (hashes==NULL)
			return 0;

		r=signal(SIGINT, &signal_handler);
		assert (r != SIG_ERR);

		while ((uname=find_unprocessed_uname(hashes))!=NULL)
			check_all_with_uname (hashes, uname, a_min, a_max, a_first_symbol_charset, a_charset, cores);

		dump_table (hashes, a_results);
	};

#ifdef _DEBUG
	_CrtDumpMemoryLeaks();

	CloseHandle (hLogFile);
#endif
};
