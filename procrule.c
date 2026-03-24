#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#ifndef _AIX
#include <getopt.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


#include "yarn.h"
#include <Judy.h>


#ifdef SPARC
#define NOTINTEL 1
#endif
#ifdef ARM
#define NOTINTEL 1
#endif
#ifdef POWERPC
#define NOTINTEL 1
#endif
#ifndef NOTINTEL

#include <emmintrin.h>
#include <xmmintrin.h>
#include <tmmintrin.h>
extern int HasSSSE3;

#endif

#ifdef ARM
#if ARM >= 7
#include <arm_neon.h>
extern int Neon;
#endif
#endif

extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;
extern char *parserules(char *line);
extern int packrules(char *line);
extern int applyrule(char *line, char *pass, int len, char *rule);

char *Rulepos = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char trhex[] = {
    17, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 16, 16, 17, 16, 16, /* 00-0f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 10-1f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 20-2f */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 16, 16, 16, 16, 16,           /* 30-3f */
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 40-4f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 50-5f */
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 60-6f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 70-7f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 80-8f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 90-9f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* a0-af */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* b0-bf */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* c0-cf */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* d0-df */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* e0-ef */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16};/* f0-ff */


 static char *Version = "$Header: /Users/dlr/src/mdfind/RCS/procrule.c,v 1.20 2026/03/24 00:11:54 dlr Exp dlr $";
/*
 * $Log: procrule.c,v $
 * Revision 1.20  2026/03/24 00:11:54  dlr
 * Replace get32 with runtime SSE2/SSSE3/NEON dispatch from mdxfind, add HasSSSE3 extern
 *
 * Revision 1.19  2026/03/17 23:49:26  dlr
 * Match MAXLINE to mdxfind.h (40KB) to prevent applyrule() output overflow.
 * ruleproc.c uses mdxfind.h MAXLINE (40KB) for internal bounds but procrule.c
 * had MAXLINE at 20KB, so applyrule() could write up to 40KB into a 20KB buffer.
 * This caused heap corruption in Phase 2 discover_worker (free(): invalid next size).
 *
 * Revision 1.18  2026/03/17 13:53:07  dlr
 * Fix buffer overflows in -G discovery mode: bounds-check HEX encoding output
 * in phase1_worker, discover_worker, and procjob (tlen*2+7 > MAXLINE+16 skips
 * the candidate). Fix chain buffer overflow in discover_worker by checking
 * accumulated length before strcpy into chainbuf.
 *
 * Revision 1.17  2026/03/16 20:49:39  dlr
 * Add -G discovery mode: find hashcat rules that transform base words into targets.
 * Phase 1: exhaustive single-rule testing (17K catalog rules, extended positions 0-Z,
 * full sXY substitutions) with lock-free per-thread wordlist slicing.
 * Phase 2: biased-random chain generation (depth 2-D) with auto-calculated sampling,
 * Bloom dedup, per-chain hit counting, output sorted by hit count (most valuable first).
 * New options: -G target_file, -D depth, -N iterations, -S sample_rate, -H min_hits.
 * Also: fast hex LUT replacing sprintf in $HEX encoding paths.
 *
 * Revision 1.16  2026/02/26 02:39:53  dlr
 * Fix SSSE3 get32: unsigned long -> uint64_t for Windows x64 LLP64 compatibility
 *
 * Revision 1.15  2026/02/23 23:08:37  dlr
 * Add -V option to display version string
 *
 * Revision 1.14  2026/02/23 23:03:10  dlr
 * Fix EOL bugs matching recent rling.c fixes: add hash_line_strip_cr() to strip embedded CR before hashing (hash/compare mismatch), fix mystrcmp/mylstrcmp newline termination checks, fix eol bounds check to use key instead of Fileinmem
 *
 * Revision 1.13  2025/11/28 18:25:57  dlr
 * Add support for base64 conversion
 *
 * Revision 1.12  2025/10/21 16:19:22  dlr
 * Add -B[count] benchmark feature
 *
 * Revision 1.11  2025/06/11 12:57:29  dlr
 * Add -s for stats output on rules/match, and -x to disable HEX output
 *
 * Revision 1.10  2025/06/11 12:38:34  dlr
 * Format line change
 *
 * Revision 1.9  2025/05/28 20:32:48  dlr
 * Multi-thread compare and generation, improve code somewhat
 *
 * Revision 1.8  2025/05/26 03:21:36  dlr
 * Improve $HEX handling.
 *
 * Revision 1.7  2025/05/26 02:05:14  dlr
 * Fix error where duplicates were not properly dropped.
 *
 * Revision 1.6  2025/05/25 23:14:18  dlr
 * Add HEX processing and -l option
 *
 * Revision 1.5  2025/05/25 18:14:04  dlr
 * Add support for multiple rule files
 *
 * Revision 1.4  2025/05/25 16:26:21  dlr
 * Added more help
 *
 * Revision 1.3  2025/05/24 03:19:34  dlr
 * Minor format changes
 *
 * Revision 1.2  2025/05/24 03:07:20  dlr
 * Added -m option, improved performance.
 *
 * Revision 1.1  2025/05/21 21:46:08  dlr
 * Initial revision
 *
 */

#include "xxh3.h"


#ifdef POWERPC
/*
#define XXH_VECTOR XXH_VSX
*/
#include <altivec.h>
#endif
#ifdef INTEL
#include <emmintrin.h>
#include <xmmintrin.h>
#endif



/* After LINELIMIT lines, threads kick in */
/* Maximume line length now 4gigabytes */
#define LINELIMIT 100000
#define MEMCHUNK (1024*1000+16)
/* Writemax is the maximum value that writev can handle */
#define WRITEMAX 2147483647

/* Bloom filter size in bits */
#define BLOOMSIZE (1LL << 30)
#define BLOOMMASK ((BLOOMSIZE/8)-1)

#define MAXCHUNK (50*1024*1024)
#define MAXRULELINE (10*1024)
#define MAXLINE (40*1024)
#define MAXRULEFILES 1024
#define MAXLINEPERCHUNK (MAXCHUNK/2/8)
#define RINDEXSIZE (MAXLINEPERCHUNK)
struct LineInfo {
    unsigned int offset;
    unsigned int len;
} *Readindex;
static int Cacheindex;
char *Readbuf;

struct RuleSort {
    uint64_t count;
    char *rule;
} *FinalRules;


struct WorkUnit {
    struct WorkUnit *next;
    lock *wulock;
    char **Sortlist;
    uint64_t ssize,count,start,end;
} *WUList;


struct Freq {
    uint32_t count,len;
    char *key;
} *Freq;
uint64_t *Histogram;
uint64_t FreqSize;

struct Infiles {
    FILE *fi;
    char *fn;
    uint64_t line;
    char *Buffer;
    size_t size, curpos, end, eof, unique, dup;
    char *curline;
    uint64_t curlen;
} *Infile;

struct InHeap {
    struct Infiles *In;
};

struct JOB {
    struct JOB *next;
    uint64_t start,end;
    int startline, numline;
    char *readbuf, *fn;
    char *plainrule,*inrule;
    struct WorkUnit *wu;
    struct LineInfo *readindex;
    int func;
} *Jobs;


#define JOB_COUNT 1
#define JOB_DEDUPE 2
#define JOB_GENHASH 3
#define JOB_MATCH 4
#define JOB_DONE 99

struct JOB *FreeHead, **FreeTail;
struct JOB *WorkHead, **WorkTail;
struct WorkUnit *WUHead, **WUTail;

lock *FreeWaiting,*WorkWaiting, *WUWaiting;
lock *Currem_lock, *ReadBuf0, *ReadBuf1;
lock *Common_lock, *Rule_lock;

char *Dupe_fn;

uint64_t Currem_global,Unique_global,Write_global, Occ_global;
uint64_t Maxdepth_global, Maxlen_global, Minlen_global;
uint64_t Line_global, HashPrime, HashMask, HashSize;
uint64_t Matchtot, Matchhits, Rulehits;
int Maxt, Workthread, ProcMode, LenMatch, IsSorted, DoDebug, NoHEX;
int64_t Bench;

/* Discovery mode (-G) globals */
char *DiscoverFile;
int MaxDepth = 3;
int64_t MaxIter = 10000000;
Pvoid_t FoundRules;
char **HotRuleList;
int HotRuleCount;
char **CatalogRules;
int CatalogCount;
char **PackedCatalog;	/* pre-packed rule buffers for Phase 1 workers */
int *CatalogValid;	/* 1 = valid rule, 0 = skip */
double SampleRate = -1.0; /* -S: Phase 2 word sampling rate (%), -1 = auto */
int MinHits = 0;	/* -H: minimum hit count to keep a rule (0 = keep all) */

struct ChainResult {
    char *chain;
    uint64_t hits;
};

struct DiscoverArg {
    int id;
    int64_t iters;
    uint32_t seed;
    struct ChainResult *results;
    int nresults;
    int alloc_results;
};

struct Phase1Arg {
    int id;
    uint64_t start, end;
    uint64_t *hits;
    uint64_t total_hits;
};



int _dowildcard = -1; /* enable wildcard expansion for Windows */

#ifdef MAXPATHLEN
#define MDXMAXPATHLEN (MAXPATHLEN)
#else
#define MDXMAXPATHLEN 5000
#endif



char *Fileinmem, *Fileend;
uint64_t Filesize;
uint64_t WorkUnitLine, WorkUnitSize, MaxMem;
char **Sortlist;
FILE *Linefile, *Fo;
Pvoid_t MRule, Match;

struct Memscale {
    double size, scale;
    char *name;
} Memscale[] = {
{1024,1, "bytes"},
{1024*1024,1024, "kbytes"},
{1024LL*1024L*1024L,1024L*1024L, "Mbytes"},
{1024LL*1024L*1024L*1024L,1024L*1024L*1024L, "Gbytes"},
{1024LL*1024L*1024L*1024L*1024L,1024LL*1024L*1024L*1024L,"Tbytes"}
};

struct Hashsizes {
    uint64_t size,prime;
} Hashsizes[] = {
{2048,1543},
{4096,3079},
{8192,6151},
{16384,12289},
{32768,24593},
{65536,49157},
{131072,98317},
{262144,196613},
{524288,393241},
{1048576,786433},
{2097152,1572869},
{4194304,3145739},
{8388608,6291469},
{16777216,12582917},
{33554432,25165843},
{67108864,50331653},
{134217728,100663319},
{268435456,201326611},
{536870912,402653189},
{1073741824,805306457},
{2147483648L,1610612741L},
{0,0}
};


struct Linelist {
    struct Linelist *next;
} *Linel;

struct Linelist **HashLine;


int Dedupe = 1, DropCR = 1;
int DoCommon = 0, SortOut = 0;
uint64_t *Common, *Bloom;
#define Commonset(offset) {__sync_or_and_fetch(&Common[(uint64_t)(offset)/64],(uint64_t)1L << ((uint64_t)(offset) & 0x3f)); }
#define Bloomset(offset) (__sync_fetch_and_or(&Bloom[(uint64_t)(offset)/64],(uint64_t)1L << ((uint64_t)(offset) & 0x3f)) & ((uint64_t)1L <<((uint64_t)(offset) & 0x3f)))
#define Commontest(offset) (Common[(uint64_t)(offset)/64] & (uint64_t)1L << ((uint64_t)(offset) & 0x3f))

/*
 * MarkD(pointer to char*, 64 bit value)
 * MarkD marks a particular entry in the Sortlist array as being a "deleted"
 * line, by setting the most significant bit of the address.  This is not
 * portable, but saves memory.  The validity of the use of this bit is
 * tested for in main, by checking the range of memory used to store the
 * file read in.
 */
uint64_t inline _MarkD(uint64_t *ptr, uint64_t val) {
    uint64_t p = *ptr;
    *ptr |= val;
    return(p);
}
#define MarkDeleted(line) _MarkD((uint64_t *)&Sortlist[line],0x8000000000000000L)




/*
 * get32: hex string to binary conversion — runtime dispatched.
 * Same implementation as mdxfind: SSSE3, SSE2, scalar, ARM NEON paths.
 */
static int get32_init(char *iline, unsigned char *dest, int len);
static int (*get32)(char *iline, unsigned char *dest, int len) = get32_init;

/* Scalar implementation — works everywhere */
static int get32_scalar(char *iline, unsigned char *dest, int len) {
  unsigned char c1, c2, *line = (unsigned char *)iline;
  int cnt = 0;
  while (cnt < len) {
     c1 = trhex[line[0]];
     c2 = trhex[line[1]];
     if (c1 > 15 || c2 > 15) break;
     *dest++ = (c1 << 4) | c2;
     line += 2;
     cnt++;
  }
  return (cnt);
}

#ifndef NOTINTEL
/* SSE2 implementation — comparison-based, no pshufb needed */
static int get32_sse2(char *iline, unsigned char *dest, int len) {
  unsigned char c1, c2, *line = (unsigned char *)iline;
  int cnt = 0;
  const __m128i ch_0 = _mm_set1_epi8('0');
  const __m128i ch_9 = _mm_set1_epi8('9');
  const __m128i ch_A = _mm_set1_epi8('A');
  const __m128i ch_F = _mm_set1_epi8('F');
  const __m128i ch_a = _mm_set1_epi8('a');
  const __m128i ch_f = _mm_set1_epi8('f');
  const __m128i off_digit = _mm_set1_epi8('0');
  const __m128i off_upper = _mm_set1_epi8('A' - 10);
  const __m128i off_lower = _mm_set1_epi8('a' - 10);
  while (cnt + 8 <= len) {
      __m128i input = _mm_loadu_si128((const __m128i *)line);
      __m128i ge_0 = _mm_cmpgt_epi8(input, _mm_sub_epi8(ch_0, _mm_set1_epi8(1)));
      __m128i le_9 = _mm_cmpgt_epi8(_mm_add_epi8(ch_9, _mm_set1_epi8(1)), input);
      __m128i is_digit = _mm_and_si128(ge_0, le_9);
      __m128i ge_A = _mm_cmpgt_epi8(input, _mm_sub_epi8(ch_A, _mm_set1_epi8(1)));
      __m128i le_F = _mm_cmpgt_epi8(_mm_add_epi8(ch_F, _mm_set1_epi8(1)), input);
      __m128i is_upper = _mm_and_si128(ge_A, le_F);
      __m128i ge_a = _mm_cmpgt_epi8(input, _mm_sub_epi8(ch_a, _mm_set1_epi8(1)));
      __m128i le_f = _mm_cmpgt_epi8(_mm_add_epi8(ch_f, _mm_set1_epi8(1)), input);
      __m128i is_lower = _mm_and_si128(ge_a, le_f);
      __m128i is_valid = _mm_or_si128(is_digit, _mm_or_si128(is_upper, is_lower));
      int inv_mask = _mm_movemask_epi8(_mm_cmpeq_epi8(is_valid, _mm_setzero_si128()));
      __m128i nibbles = _mm_or_si128(
          _mm_and_si128(is_digit, _mm_sub_epi8(input, off_digit)),
          _mm_or_si128(
              _mm_and_si128(is_upper, _mm_sub_epi8(input, off_upper)),
              _mm_and_si128(is_lower, _mm_sub_epi8(input, off_lower))));
      __m128i packed = _mm_or_si128(
          _mm_and_si128(_mm_slli_epi16(nibbles, 4), _mm_set1_epi16(0x00F0)),
          _mm_srli_epi16(_mm_and_si128(nibbles, _mm_set1_epi16(0x0F00)), 8));
      packed = _mm_and_si128(packed, _mm_set1_epi16(0x00FF));
      packed = _mm_packus_epi16(packed, _mm_setzero_si128());
      if (inv_mask == 0) {
          _mm_storel_epi64((__m128i *)dest, packed);
          cnt += 8; dest += 8; line += 16;
      } else {
          int valid_bytes = __builtin_ctz(inv_mask) / 2;
          uint64_t r;
          _mm_storel_epi64((__m128i *)&r, packed);
          memcpy(dest, &r, valid_bytes);
          cnt += valid_bytes; dest += valid_bytes; line += valid_bytes * 2;
          break;
      }
  }
  while (cnt < len) {
     c1 = trhex[line[0]]; c2 = trhex[line[1]];
     if (c1 > 15 || c2 > 15) break;
     *dest++ = (c1 << 4) | c2; line += 2; cnt++;
  }
  return (cnt);
}

/* SSSE3 implementation — pshufb LUT */
__attribute__((target("ssse3")))
static int get32_ssse3(char *iline, unsigned char *dest, int len) {
  unsigned char c1, c2, *line = (unsigned char *)iline;
  int cnt = 0;
  const __m128i sub_lut = _mm_setr_epi8(0,0,0,0x30,0x37,0,0x57,0, 0,0,0,0,0,0,0,0);
  const __m128i hi_valid = _mm_setr_epi8(0,0,0,1,2,0,4,0, 0,0,0,0,0,0,0,0);
  const __m128i lo_valid = _mm_setr_epi8(1,0x07,0x07,0x07,0x07,0x07,0x07,1, 1,1,0,0,0,0,0,0);
  const __m128i lomask = _mm_set1_epi8(0x0F);
  const __m128i pack_hi = _mm_set1_epi16(0x00F0);
  const __m128i pack_lo = _mm_set1_epi16(0x0F00);
  const __m128i compact = _mm_setr_epi8(0,2,4,6,8,10,12,14, -1,-1,-1,-1,-1,-1,-1,-1);
  while (cnt + 8 <= len) {
      __m128i input = _mm_loadu_si128((const __m128i *)line);
      __m128i hi = _mm_and_si128(_mm_srli_epi16(input, 4), lomask);
      __m128i lo = _mm_and_si128(input, lomask);
      __m128i nibbles = _mm_sub_epi8(input, _mm_shuffle_epi8(sub_lut, hi));
      __m128i vcheck = _mm_and_si128(_mm_shuffle_epi8(hi_valid, hi), _mm_shuffle_epi8(lo_valid, lo));
      int inv_mask = _mm_movemask_epi8(_mm_cmpeq_epi8(vcheck, _mm_setzero_si128()));
      __m128i packed = _mm_or_si128(
          _mm_and_si128(_mm_slli_epi16(nibbles, 4), pack_hi),
          _mm_srli_epi16(_mm_and_si128(nibbles, pack_lo), 8));
      __m128i result = _mm_shuffle_epi8(packed, compact);
      if (inv_mask == 0) {
          _mm_storel_epi64((__m128i *)dest, result);
          cnt += 8; dest += 8; line += 16;
      } else {
          int valid_bytes = __builtin_ctz(inv_mask) / 2;
          uint64_t r;
          _mm_storel_epi64((__m128i *)&r, result);
          memcpy(dest, &r, valid_bytes);
          cnt += valid_bytes; dest += valid_bytes; line += valid_bytes * 2;
          break;
      }
  }
  while (cnt < len) {
     c1 = trhex[line[0]]; c2 = trhex[line[1]];
     if (c1 > 15 || c2 > 15) break;
     *dest++ = (c1 << 4) | c2; line += 2; cnt++;
  }
  return (cnt);
}
#endif /* !NOTINTEL */

#if defined(ARM) && defined(__aarch64__)
static int get32_neon64(char *iline, unsigned char *dest, int len) {
  unsigned char c1, c2, *line = (unsigned char *)iline;
  int cnt = 0;
  const uint8x16_t sub_lut = {0,0,0,0x30,0x37,0,0x57,0, 0,0,0,0,0,0,0,0};
  const uint8x16_t hi_valid = {0,0,0,1,2,0,4,0, 0,0,0,0,0,0,0,0};
  const uint8x16_t lo_valid = {1,7,7,7,7,7,7,1, 1,1,0,0,0,0,0,0};
  const uint8x16_t lomask = vdupq_n_u8(0x0F);
  while (cnt + 8 <= len) {
    uint8x16_t input = vld1q_u8(line);
    uint8x16_t hi = vandq_u8(vshrq_n_u8(input, 4), lomask);
    uint8x16_t lo = vandq_u8(input, lomask);
    uint8x16_t vcheck = vandq_u8(vqtbl1q_u8(hi_valid, hi), vqtbl1q_u8(lo_valid, lo));
    uint8x16_t vzero = vceqq_u8(vcheck, vdupq_n_u8(0));
    uint64_t reject = vgetq_lane_u64(vreinterpretq_u64_u8(vzero), 0) |
                       vgetq_lane_u64(vreinterpretq_u64_u8(vzero), 1);
    uint8x16_t nibbles = vsubq_u8(input, vqtbl1q_u8(sub_lut, hi));
    uint16x8_t wide = vreinterpretq_u16_u8(nibbles);
    uint16x8_t pk = vorrq_u16(vshlq_n_u16(vandq_u16(wide, vdupq_n_u16(0x000F)), 4), vshrq_n_u16(wide, 8));
    uint8x8x2_t uzp = vuzp_u8(vget_low_u8(vreinterpretq_u8_u16(pk)), vget_high_u8(vreinterpretq_u8_u16(pk)));
    if (reject == 0) { vst1_u8(dest, uzp.val[0]); cnt += 8; dest += 8; line += 16; }
    else {
      uint8_t vzbuf[16]; int vb = 0, k; vst1q_u8(vzbuf, vzero);
      for (k = 0; k < 16; k += 2) { if (vzbuf[k] || vzbuf[k+1]) break; vb++; }
      if (vb > 0) { uint8_t rb[8]; vst1_u8(rb, uzp.val[0]); memcpy(dest, rb, vb); cnt += vb; dest += vb; line += vb * 2; }
      break;
    }
  }
  while (cnt < len) { c1 = trhex[line[0]]; c2 = trhex[line[1]]; if (c1 > 15 || c2 > 15) break; *dest++ = (c1 << 4) | c2; line += 2; cnt++; }
  return (cnt);
}
#elif defined(ARM) && ARM >= 7
static int get32_neon32(char *iline, unsigned char *dest, int len) {
  unsigned char c1, c2, *line = (unsigned char *)iline;
  int cnt = 0;
  if (Neon) {
    const uint8x8_t sub_lut_lo = {0,0,0,0x30,0x37,0,0x57,0}, sub_lut_hi = {0,0,0,0,0,0,0,0};
    const uint8x8_t hi_valid_lo = {0,0,0,1,2,0,4,0}, hi_valid_hi = {0,0,0,0,0,0,0,0};
    const uint8x8_t lo_valid_lo = {1,7,7,7,7,7,7,1}, lo_valid_hi = {1,1,0,0,0,0,0,0};
    const uint8x8_t lomask = vdup_n_u8(0x0F);
    uint8x8x2_t sub_tbl = {{sub_lut_lo, sub_lut_hi}}, hiv_tbl = {{hi_valid_lo, hi_valid_hi}}, lov_tbl = {{lo_valid_lo, lo_valid_hi}};
    while (cnt + 4 <= len) {
      uint8x8_t input = vld1_u8(line);
      uint8x8_t hi = vand_u8(vshr_n_u8(input, 4), lomask), lo = vand_u8(input, lomask);
      uint8x8_t vcheck = vand_u8(vtbl2_u8(hiv_tbl, hi), vtbl2_u8(lov_tbl, lo));
      uint64_t check64; vst1_u8((uint8_t *)&check64, vceq_u8(vcheck, vdup_n_u8(0)));
      uint8x8_t nibbles = vsub_u8(input, vtbl2_u8(sub_tbl, hi));
      uint16x4_t wide = vreinterpret_u16_u8(nibbles);
      uint16x4_t pk = vorr_u16(vshl_n_u16(vand_u16(wide, vdup_n_u16(0x000F)), 4), vshr_n_u16(wide, 8));
      uint8_t rb[8]; vst1_u8(rb, vreinterpret_u8_u16(pk));
      if (check64 == 0) { dest[0]=rb[0]; dest[1]=rb[2]; dest[2]=rb[4]; dest[3]=rb[6]; cnt+=4; dest+=4; line+=8; }
      else {
        uint8_t vzbuf[8]; int vb=0, k; vst1_u8(vzbuf, vceq_u8(vcheck, vdup_n_u8(0)));
        for (k=0; k<8; k+=2) { if (vzbuf[k]||vzbuf[k+1]) break; vb++; }
        for (k=0; k<vb; k++) dest[k]=rb[k*2]; cnt+=vb; dest+=vb; line+=vb*2; break;
      }
    }
  }
  while (cnt < len) { c1 = trhex[line[0]]; c2 = trhex[line[1]]; if (c1 > 15 || c2 > 15) break; *dest++ = (c1 << 4) | c2; line += 2; cnt++; }
  return (cnt);
}
#endif

/* Lazy-init dispatcher */
static int get32_init(char *iline, unsigned char *dest, int len) {
#ifndef NOTINTEL
  if (HasSSSE3) get32 = get32_ssse3;
  else get32 = get32_sse2;
#elif defined(ARM) && defined(__aarch64__)
  get32 = get32_neon64;
#elif defined(ARM) && ARM >= 7
  get32 = Neon ? get32_neon32 : get32_scalar;
#else
  get32 = get32_scalar;
#endif
  return get32(iline, dest, len);
}

/* Fast byte-to-hex lookup table: hexlut[byte] gives two ASCII hex chars */
static const char hexlut[512] =
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

char b64[]       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock(unsigned char in[], char out[], int len) {
  out[0] = b64[in[0] >> 2];
  out[1] = b64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
  out[2] = (unsigned char) (len > 1 ? b64[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)] : '=');
  out[3] = (unsigned char) (len > 2 ? b64[in[2] & 0x3f] : '=');
  out[4] = '\0';
}

/* encode - base64 encode a stream, adding padding if needed */
int b64_encode(char *clrstr, char *b64dst, int inlen) {
  unsigned char in[3];
  char *out;
  int i, len = 0, outlen = 0;
  int j = 0;

  b64dst[0] = '\0';
  out = b64dst;
  while (inlen) {
    len = 3;
    if (inlen < len)
      len = inlen;
    in[0] = in[1] = in[2] = 0;
    for (i = 0; i < len; i++) {
      in[i] = (unsigned char) clrstr[j++];
    }
    if (len) {
      encodeblock(in, out, len);
      out += 4;
      outlen += 4;
    }
    inlen -= len;
  }
  *out = 0;
  return (outlen);
}





/*
 * prstr prints a \n terminated string, or up to n characters
 */

void prstr(char *s, int n) {
     uint64_t RC = (uint64_t)(s) & 0x7fffffffffffffffL;
     if (s != (char *)RC) fprintf(stderr,"(deleted) ");
     s = (char *)RC;
     while (n-- && *s != '\n') {if (*s >= ' ' && *s < 0x7f) fputc(*s++,stderr); else fprintf(stderr,"0x%02x",*s);}
     fputc(*s,stderr);
}

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif
void current_utc_time(struct timespec *ts) {
#ifdef __MACH__ // OS X does not have clock_gettime, use clock_get_time
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

/*
 * findeol(pointer, length)
 *
 * findeol searches for the next eol character (\n, 0x0a) in a string
 *
 * The Intel version uses SSE to process 64 bits at a time.  This only
 * is able to work because I ensure that the Fileinmem buffer has adequate
 * space (16 bytes) following it to ensure that reading past the end won't
 * read memory not available and cause a fault.
 *
 * This is important to the operation of this program, and care should be
 * taken to ensure that the performance of this function is kept fast
 */

#if !defined(POWERPC) && !defined(INTEL)
#define findeol(a,b) memchr(a,10,b)
#endif

#ifdef POWERPC
#define findeol(a,b) memchr(a,10,b)
#endif

#ifdef INTEL
inline char *findeol(char *s, int64_t l) {
  unsigned int align, res, f;
  __m128i cur, seek;

  if (l <=0) return (NULL);

  seek = _mm_set1_epi8('\n');
  align = ((uint64_t) s) & 0xf;
  s = (char *) (((uint64_t) s) & 0xfffffffffffffff0L);
  cur = _mm_load_si128((__m128i const *) s);
  res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur)) >> align;

  f = ffs(res);
  res <<= align;
  if (f && (f <= l))
    return (s + ffs(res) - 1);
  s += 16;
  l -= (16 - align);

  while (l >= 16) {
    cur = _mm_load_si128((__m128i const *) s);
    res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur));
    f = ffs(res);
    if (f)
      return (s + f - 1);
    s += 16;
    l -= 16;
  }
  if (l > 0) {
    cur = _mm_load_si128((__m128i const *) s);
    res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur));
    f = ffs(res);
    if (f && (f <= l)) {
      return (s + f - 1);
    }
  }
  return (NULL);
}
#endif

    
/* get_nprocs
 *
 * Returns the available number of threads that this program has access to
 * and this value is used to set the number of simultaneous work threads
 * for large files.
 */
#ifdef _SC_NPROCESSORS_ONLN
#ifdef MACOSX
#include <sys/sysctl.h>
int get_nprocs() {
    int numCPUs;
    size_t len = sizeof(numCPUs);
    int mib[2] = { CTL_HW, HW_NCPU };
    if (sysctl(mib, 2, &numCPUs, &len, NULL, 0))
      return 1;
    return numCPUs;
}
#else
int get_nprocs() {
    int numCPUs;
    numCPUs = sysconf(_SC_NPROCESSORS_ONLN);
    if (numCPUs <=0)
      numCPUs = 1;
    return(numCPUs);
}
#endif
#endif
#ifdef SPARC
#ifndef AIX
int get_nprocs() { return(1); }
#endif
#endif
#ifdef _WIN32
#include <windows.h>

int get_nprocs() {
    SYSTEM_INFO SysInfo;
    ZeroMemory(&SysInfo,sizeof(SYSTEM_INFO));
    GetSystemInfo(&SysInfo);
    return SysInfo.dwNumberOfProcessors;
}
#endif



/*
 * commify takes a large integer (long long), and returns a char *
 * to a static space with commas inserted to make large numbers more
 * readable.
 */
static char Commify[128];
char *commify(uint64_t source) {
  char temp[128];
  char *s, *d;
  int len, targlen, x;

  sprintf(temp, "%"PRIu64, source);
  len = strlen(temp);
  targlen = len + ((len - 1) / 3);
  d = &Commify[targlen];
  s = &temp[len];
  *d-- = *s--;
  for (x = 1; x <= len && d >= Commify; x++) {
    *d-- = *s--;
    if ((x % 3) == 0 && x && d >= Commify)
      *d-- = ',';
  }
  return (Commify);
}

/*
 * hash_line_strip_cr - compute XXH3 hash with \r characters stripped.
 *
 * The comparison functions (mystrcmp/mylstrcmp) skip \r characters,
 * so two lines differing only in embedded \r compare as equal.
 * The hash must be consistent: lines that compare equal must hash equal.
 * Fast path (no \r in line) calls XXH3_64bits directly.
 */
static uint64_t hash_line_strip_cr(const char *key, int64_t llen) {
    if (llen <= 0)
	return XXH3_64bits(key, 0);
    if (!memchr(key, '\r', llen))
	return XXH3_64bits(key, llen);
    /* Strip \r matching comparison behavior: if byte is \r, take next byte */
    char smallbuf[4096];
    char *buf = (llen <= (int64_t)sizeof(smallbuf)) ? smallbuf : malloc(llen);
    const unsigned char *src = (const unsigned char *)key;
    const unsigned char *end = src + llen;
    int64_t newlen = 0;
    unsigned char c;
    while (src < end) {
	c = *src++;
	if (c == '\r' && src < end)
	    c = *src++;
	buf[newlen++] = c;
    }
    uint64_t hash = XXH3_64bits(buf, newlen);
    if (buf != smallbuf) free(buf);
    return hash;
}

/*
 * mystrcmp compares two \n-terminated strings
 * Just like strcmp, but instead of nul termination...
 */
int mystrcmp(const char *a, const char *b) {
  const unsigned char *s1 = (const unsigned char *) a;
  const unsigned char *s2 = (const unsigned char *) b;
  unsigned char c1, c2;
      do
	{
	  c1 = (unsigned char) *s1++;
	  if (c1 == '\r')
	      c1 = (unsigned char) *s1++;
	  c2 = (unsigned char) *s2++;
	  if (c2 == '\r')
	      c2 = (unsigned char) *s2++;
	  if (c1 == '\n')
	    return (c2 == '\n') ? 0 : -1;
	  if (c2 == '\n')
	    return 1;
	}
      while (c1 == c2);
      return c1 - c2;
}

int mylstrcmp(const char *a, const char *b) {
  const unsigned char *s1 = (const unsigned char *) a;
  const unsigned char *s2 = (const unsigned char *) b;
  unsigned char c1, c2;
  int len, ilen = LenMatch;
  if (ilen == 0) {
      do
	{
	  c1 = (unsigned char) *s1++;
	  if (c1 == '\r')
	      c1 = (unsigned char) *s1++;
	  c2 = (unsigned char) *s2++;
	  if (c2 == '\r')
	      c2 = (unsigned char) *s2++;
	  if (c1 == '\n')
	    return (c2 == '\n') ? 0 : -1;
	  if (c2 == '\n')
	    return 1;
	}
      while (c1 == c2);
      return c1 - c2;
  } else {
      len = 0;
      do
	{
	  c1 = (unsigned char) *s1++;
	  if (c1 == '\r')
	      c1 = (unsigned char) *s1++;
	  c2 = (unsigned char) *s2++;
	  if (c2 == '\r')
	      c2 = (unsigned char) *s2++;
	  if (c1 == '\n')
	    return (c2 == '\n') ? 0 : -1;
	  if (c2 == '\n')
	    return 1;
	}
      while (c1 == c2 && ++len < ilen);
      return c1 - c2;
  }
}


/*
 * comp1 compares two Sortline[] strings, and removes the "deleted"
 * bit in case one or more of the strings are in the deleted state.
 */
int comp1(const void *a, const void *b) {
    char *a1 = *((char **)a);
    char *b1 = *((char **)b);
    a1 = (char *)((uint64_t)a1 & 0x7fffffffffffffffL);
    b1 = (char *)((uint64_t)b1 & 0x7fffffffffffffffL);
    return(mystrcmp(a1,b1));
}
/*
 * comp2 compares a key against the (potentially deleted) Sortline[] entry
 * it removes the deleted bit before comparison
 */
int comp2(const void *a, const void *b) {
    char *a1 = (char *)a;
    char *b1 = (char *)(((uint64_t)*((char **)b)) & 0x7fffffffffffffffL);
    return(mylstrcmp(a1,b1));
}
/* comp3 compares the addresses pointed to by the Sortline[] array.
 * This is used to sort the array back into input-file line order, but also
 * moves all of the deleted lines to the end.
 */
int comp3(const void *a, const void *b) {
    uint64_t a1 = (uint64_t)(*((char **)a));
    uint64_t b1 = (uint64_t)(*((char **)b));
    if (a1 > b1) return(1);
    if (a1 < b1) return(-1);
    return(0);
}


/*
 * comp5 is used for the frequency analysis. The sort here
 * does double duty, in that there can be "gaps" in the frequency
 * table structure, because it is processed with many threads.
 * If all words in the list are unique, there will be no gaps
 * If there are, comp5 helps to sort them to the end of the list
 * by looking for null pointers
 */
int comp5(const void *a, const void *b) {
    struct Freq *a1 = (struct Freq *)a;
    struct Freq *b1 = (struct Freq *)b;
    if (!a1->key || !b1->key) {
	if (!a1->key) return(1);
	if (!b1->key) return(-1);
	return(0);
    }
    if (a1->count < b1->count) return(1);
    if (a1->count > b1->count) return(-1);
    return(mystrcmp(a1->key,b1->key));
}


/*
 * MDXALIGN forces the process to start on an appropriate boundary.  Windows
 * gets picky about the offset of a particular thread function
 */
#ifdef MDX_BIT32
#ifndef NOTINTEL
#define MDXALIGN __attribute__((force_align_arg_pointer))
#else
#define MDXALIGN
#endif
#else
#define MDXALIGN
#endif

/*
 * procjob is the main processing thread function.  It runs as a separate
 * thread, and up to Maxt threads can be running simultaneously.
 * In most cases, jobs are pulled from the head of the WorkWaiting
 * list, processed, and then the job is returned to the FreeWaiting list.
 * The exception is JOB_DONE, which stays on the head of the list, to
 * allow a single job to terminate all of the active procjob threads.
 *
 * JOB_COUNT is the first operation called. It finds each line in the file
 * and returns Sortlist[]-style entries into a buffer (which is temporarily
 * allocated from the remove-file-read-buffers).  This is done so that
 * Sortlist can be allocated from contiguous space, making realloc much
 * cheaper (both on time and memory). Large numbers of lines can then
 * expands the Sortlist until the whole file is processed.  The test
 * cases for rling have hundreds of millions of lines, or billions.  This
 * is also the process that removes Windows-style (\r\n) line termination
 * from the input file.
 *
 * JOB_GENHASH generates the hash table for groups of lines.  This
 * use a compare-and-swap method of locking the linked list built from the
 * hash table, rather than a global lock on the hash table, improving
 * performance somewhat.  It is a linked list, however, and is searched
 * sequentially.
 *
 * JOB_DONE leaves the job on the work list, and terminates the thread.
 */

MDXALIGN void procjob(void *dummy) {
    struct JOB *job;
    struct WorkUnit *wu, *wulast, *wunext;
    struct Linelist *cur, *next, *last;
    char **sorted, *key, *newline, *eol;
    char *Workline, *Workline2, *Workline3, *outline, *linebuf;
    char *s,*d,*ruleword;
    char *cache;
    int cachepos,cachemax = MAXLINE*3;;
    uint64_t x, unique, occ, rem,thisnum, crc, index, j, RC, COM, thisend;
    int64_t tlen, llen, wlen, maxdepth, minlen, maxlen, bench;
    int res, curline, numline, ch, delflag, outcount;
    int issorted;
    struct timespec starttime,curtime;
    double wtime;
    Word_t *PV;

    Workline = malloc(MAXLINE+16);
    Workline2 = malloc(MAXLINE+16);
    Workline3 = malloc(MAXLINE+16);
    outline = malloc(MAXLINE+16);
    linebuf = malloc(MAXLINE*3 + 16);
    cache = malloc(cachemax + 16);
    if (!cache || !Workline || !Workline2 || !Workline3 || !outline || !linebuf) {
        fprintf(stderr,"Out of memory in procjob\n");
	exit(1);
    }
    cachepos = 0;
    while (1) {
        possess(WorkWaiting);
	wait_for(WorkWaiting, NOT_TO_BE, 0);
	job = WorkHead;
	if (!job || job->func == 0) {
	    fprintf(stderr,"Job null - exiting\n");
	    exit(1);
	}
	if (job->func == JOB_DONE) {
	    release(WorkWaiting);
	    return;
	}
	WorkHead = job->next;
	if (WorkHead == NULL)
	    WorkTail = &WorkHead;
	twist(WorkWaiting, BY, -1);
	job->next = NULL;

	switch(job->func) {
	    case JOB_COUNT:
	        wu = job->wu;
		j = wu->count = 0;
		index = job->start;
		wu->start = index;
		minlen = (uint32_t) -1L;
		maxlen = 0;
		issorted = IsSorted;
		do {
		    newline = &Fileinmem[index];
		    wu->Sortlist[j++] = newline;
		    eol = findeol(newline,job->end-index);
		    if (!eol)
		       eol = &Fileinmem[job->end];
		    llen = eol - newline;
		    index += llen + 1;
		    if (llen > maxlen) maxlen = llen;
		    if (llen < minlen) minlen = llen;
		    if (index >= job->end || j >= wu->ssize) {
		        wu->count = j;
		        wu->end = index;
			possess(WUWaiting);
			possess(wu->wulock);
			wu->next = NULL;
			for (wulast = NULL, wunext = WUHead; wunext; wulast=wunext,wunext = wunext->next)
			    if (wu->start < wunext->start)
			        break;
			if (wunext == NULL) {
			    *WUTail = wu;
			    WUTail = &(wu->next);
			} else {
			   if (wulast == NULL) {
			       WUHead = wu;
			       wu->next = wunext;
			    } else {
			        if (WUTail == &(wunext->next)) {
				    *WUTail = wu;
				    WUTail = &(wu->next);
				} else {
				    wu->next = wunext;
				    wulast->next = wu;
				}
			    }
			}
			twist(wu->wulock, BY, +1);
			twist(WUWaiting,BY,+1);
			possess(wu->wulock);
			wait_for(wu->wulock,TO_BE,0);
			release(wu->wulock);
			wu->start = index;
			j = wu->count = 0;
		    }
		    if (issorted) {
			if (index < job->end && mystrcmp(newline,&Fileinmem[index]) > 0) {
			    issorted = 0;
			    while (issorted != IsSorted)
				__sync_val_compare_and_swap(&IsSorted,IsSorted,issorted);
			}
		    }
		} while (index < job->end);
		while (maxlen > Maxlen_global)
		    __sync_val_compare_and_swap(&Maxlen_global,Maxlen_global,maxlen);
		while (minlen < Minlen_global)
		    __sync_val_compare_and_swap(&Minlen_global,Minlen_global,minlen);
		break;

	    case JOB_DEDUPE:
		key = Sortlist[job->start];
		unique = 1; rem =0;
		for (index=job->start+1; index < job->end; index++) {
		    if (mylstrcmp(key,Sortlist[index]) == 0) {
			rem++;
			MarkDeleted(index);
		    } else {
			unique++;
			key = Sortlist[index];
		    }
		}
		__sync_add_and_fetch(&Currem_global,rem);
		__sync_add_and_fetch(&Unique_global,unique);
		break;


	    case JOB_GENHASH:
		occ = unique = rem = 0;
		maxdepth = 0;
	        ch = Dedupe;
		if (HashMask) {
		    int lastp = 99, progress;
		    for (index = job->start; index < job->end; index++) {
			if (job->start == 0){
			    progress = (index*100)/job->end;
			    if (progress != lastp) {
				lastp = progress;
				fprintf(stderr,"%c%c%c%c%3d%%",8,8,8,8,progress);fflush(stderr);
			    }
			}
			key = Sortlist[index];
			eol = findeol(key,Fileend-key);
			if (!eol) eol = Fileend;
			if (eol > key && eol[-1] == '\r') eol--;
			llen = eol - key;
			crc =  hash_line_strip_cr(key,llen);
			j = crc & HashMask;
		        next = &Linel[index];
		        next->next = HashLine[j];
			if (!next->next && __sync_bool_compare_and_swap(&HashLine[j],next->next,next)) {
			    unique++;occ++;
			    continue;
			}
			delflag =  (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
			for (x=0,last = cur = HashLine[j]; !delflag && cur; x++) {
			    if (ch) {
				res = comp2(key,&Sortlist[cur - Linel]);
				if (res == 0) {
				    delflag = 1;
				    MarkDeleted(index);
				    rem++;
				    break;
				}
			    }
			    last = cur;
			    cur = cur->next;
			}
			if (x > maxdepth) maxdepth = x;
			if (!delflag) {
			    next->next = NULL;
			    while (last) {
			        if (__sync_bool_compare_and_swap(&last->next,next->next,next))
				break;
				last = last->next;
			    }
			    unique++;
			}
		    }
		} else {
		    int lastp = 99, progress;
		    for (index = job->start; index < job->end; index++) {
			if (job->start == 0){
			    progress = (index*100)/job->end;
			    if (progress != lastp) {
				lastp = progress;
				fprintf(stderr,"%c%c%c%c%3d%%",8,8,8,8,progress);fflush(stderr);
			    }
			}
			key = (char *)((uint64_t)Sortlist[index] & 0x7fffffffffffffffL);
			eol = findeol(key,Fileend-key);
			if (!eol) eol = Fileend;
			if (eol > key && eol[-1] == '\r') eol--;
			llen = eol - key;
			crc =  hash_line_strip_cr(key,llen);
			j = crc % HashPrime;
		        next = &Linel[index];
		        next->next = HashLine[j];
			if (!next->next && __sync_bool_compare_and_swap(&HashLine[j],next->next,next)) {
			    unique++;occ++;
			    continue;
			}
			delflag =  (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
			for (x=0,last = cur = HashLine[j]; !delflag && cur; x++) {
			    if (ch) {
				res = comp2(key,&Sortlist[cur - Linel]);
				if (res == 0) {
				    delflag = 1;
				    MarkDeleted(index);
				    rem++;
				    break;
				}
			    }
			    last = cur;
			    cur = cur->next;
			}
			if (x > maxdepth) maxdepth = x;
			if (!delflag) {
			    next->next = NULL;
			    while (last) {
			        if (__sync_bool_compare_and_swap(&last->next,next->next,next))
				break;
				last = last->next;
			    }
			    unique++;
			}
		    }

		}
		if (maxdepth > Maxdepth_global) {
		    while (!__sync_bool_compare_and_swap(&Maxdepth_global,Maxdepth_global,maxdepth));
		}
		__sync_add_and_fetch(&Currem_global, rem);
		__sync_add_and_fetch(&Unique_global, unique);
		__sync_add_and_fetch(&Occ_global, occ);
		break;



	    case JOB_MATCH:
		cachepos = 0;
		for (index = job->start; index < job->end; index++) {
		    delflag =  (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
		    if (delflag) continue;
		    key = (char *)((uint64_t)Sortlist[index] & 0x7fffffffffffffffL);
		    eol = findeol(key,Fileend-key);
		    if (!eol) eol = Fileend;
		    if (eol > key && eol[-1] == '\r') eol--;
		    wlen = llen = eol - key;
		    if (Bench) {
			strncpy(Workline,key,wlen);
		    }
		    if (wlen > 5 && strncmp(key, "$HEX[", 5) == 0) {
			wlen = llen = get32(key+5,(unsigned char *)Workline,wlen-6);
			key = Workline;
			key[wlen] = 0;
		    }
		    if (Bench) {
    			current_utc_time(&starttime);
			for (bench=0; bench < Bench; bench++) 
			    tlen = applyrule(key,outline,llen,job->inrule);
    			current_utc_time(&curtime);
			wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
			wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
			wtime *= 1000000000.0/(double)Bench;
		        fprintf(stderr,"%.4f ns for len %" PRId64 ", \"%s\" rule: %s\n",wtime,llen,Workline,job->plainrule);
			llen = tlen;
		    } else {
		        llen = applyrule(key,outline,llen,job->inrule);
		    }
		    if (llen <= 0) continue;
		    if ((wlen == llen) && strncmp(key,outline,wlen) == 0)
			continue;
		    for (delflag=0,x=0,s=outline; NoHEX == 0 && x< llen; s++,x++) {
		        if ((signed char)(*s) < '!' || *s == ':') {
		            delflag =1;
			    break;
			}
		    }
		    ruleword = outline;
		    if (delflag) {
			/* HEX output is 5 + llen*2 + 2 bytes; skip if it won't fit */
			if (llen * 2 + 7 > MAXLINE + 16) continue;
			memcpy(Workline2,"$HEX[",5);
			d = Workline2 + 5;
		        for (x=0,s=outline; x < llen; x++,s++,d += 2) {
			    *(unsigned short *)d = *(unsigned short *)&hexlut[((unsigned char)*s)*2];
			}
			*d++=']';
			*d = 0;
			llen = d-Workline2;
			ruleword = Workline2;
		    }
		    if (Matchtot) {
			JSLG(PV,Match,(uint8_t *)ruleword);
			if (PV) {
			    if (Linefile) {
			        for (delflag=x=0,s=key; NoHEX ==0 && x < wlen; x++,s++) {
				    if ((signed char)(*s) < '!' || *s == ':') {
					delflag =1;
					break;
				    }
				}
				if (delflag) {
				    memcpy(linebuf,"$HEX[",5);
				    d = linebuf + 5;
				    for (x=0,s=key; x < wlen; x++,s++,d += 2) {
					*(unsigned short *)d = *(unsigned short *)&hexlut[((unsigned char)*s)*2];
				    }
				    *d++=']';
				} else {
				    strncpy(linebuf,key,wlen);
				    d = linebuf + wlen;
				}
				*d++ = ':';
				for (s = job->plainrule,x=0; *s && x < MAXLINE; s++,x++) {
				    if (*s == '\r' || *s == '\n') break;
				    *d++ = *s;
				}
				*d++ = ':';
				strncpy(d,ruleword,llen);
				d+=llen;
				*d++ = '\n';
				fwrite(linebuf,d-linebuf,1,Linefile);
			    }
			    possess(Rule_lock);
			    if (DoDebug > 1) {
				fprintf(stderr,"Match for \"");
				fwrite(key,wlen,1,stderr);
				fprintf(stderr,"\" to \"%s\"\n",ruleword);
				fprintf(stderr,"Rule: %s\n",job->plainrule);
			    }
			    JSLI(PV,MRule,(uint8_t *)job->plainrule);
			    if (!PV) {
			       fprintf(stderr,"Out of memory processing matches\n");
			       exit(1);
			    }
			    if (*PV == 0) Rulehits++;
			    *PV = *PV + +1;
			    Matchhits++;
			    release(Rule_lock);
			}
		    } else {
			ruleword[llen]='\n';
			if ((cachepos + llen + 1) > cachemax) {
			    fwrite(cache,cachepos,1,Fo);
			    cachepos = 0;
			}
			memmove(cache+cachepos,ruleword,llen+1);
			cachepos += llen + 1;
		    }
		}
		if (cachepos) {
		    fwrite(cache,cachepos,1,Fo);
		    cachepos = 0;
		}
	    	break;
	    default:
	        fprintf(stderr,"Unknown job function: %d\n",job->func);
		exit(1);
	}
	job->func = 0;
	possess(FreeWaiting);
	*FreeTail = job;
	FreeTail = &(job->next);
	twist(FreeWaiting, BY, +1);
    }
}

/*
 * filljob is used to supply data to the JOB_COUNT operation of the procjob.
 *
 * It is run as a separate thread in order to make the mainline code as
 * simple as possible - this just fills the WorkWaiting list with
 * data blocks for the JOB_COUNT function, and when it is out of data,
 * waits for the queue to drain and exits.
 */
MDXALIGN void filljob(void *dummy) {
    struct JOB *job;
    uint64_t work,filesize;
    uint64_t index;
    char *eol, *thisline;
    int issorted;


    IsSorted = issorted = 1;
    filesize = Filesize;
    work = 0;
    while (work < filesize) {
	possess(FreeWaiting);
	wait_for(FreeWaiting, NOT_TO_BE,0);
	job = FreeHead;
	FreeHead = job->next;
	if (FreeHead == NULL) FreeTail = &FreeHead;
	twist(FreeWaiting, BY, -1);
	job->next = NULL;
	job->func = JOB_COUNT;
	job->start = work;
	job->end = work + WorkUnitLine;
	if (job->end >= filesize) {
	    job->end = filesize;
	} else {
	    eol = findeol(&Fileinmem[job->end],filesize-job->end);
	    if (!eol || eol > &Fileinmem[filesize]) {
		job->end = filesize;
	    } else {
		if (issorted) {
		    for (index=job->end-1; index > job->start; index--) {
			if (Fileinmem[index] == '\n') {
			    index++;
			    break;
			}
		    }
		    if (mystrcmp(&Fileinmem[index],eol+1) > 0) {
			issorted = 0;
			while (issorted != IsSorted)
			    __sync_val_compare_and_swap(&IsSorted,IsSorted,issorted);
		    }
		}
		job->end = (eol-Fileinmem) + 1;
	    }
	}
	work = job->end;
	if (Workthread < Maxt) {
	    launch(procjob,NULL);
	    Workthread++;
	}
	possess(WorkWaiting);
	*WorkTail = job;
	WorkTail = &(job->next);
	twist(WorkWaiting,BY,+1);
    }
    possess(FreeWaiting);
    wait_for(FreeWaiting, TO_BE, Maxt);
    release(FreeWaiting);
    possess(Common_lock);
    twist(Common_lock,TO,+1);
    return;
}


/*
 * cacheline is called from main, and reads the input file into buffers
 * By double-buffering, and using locks to keep track of the buffer
 * usage, it is able to keep the input data busy.  It breaks each
 * buffer into "lines", by looking for the eol (\n).  If there is a
 * Windows-style eol (\r\n), this is changed to \n\n, and the length
 * reduced by one.
 *
 * While the input file lines are truly "any length", the remove file
 * lines are limited to a bit less than half the buffer size in length.
 * So, if the buffers are 50 megabytes, then the maximum line length permitted
 * is around 25 megabytes.
 *
 * In practice, I doubt this will affect anyone, but it is something to
 * be aware of
 */
unsigned int cacheline(FILE *fi,char **mybuf,struct LineInfo **myindex) {
    char *curpos,*readbuf, *f;
    static unsigned int nextline;
    unsigned int dest, curline,len, Linecount, rlen;
    struct LineInfo *readindex;
    int cacheindex;
    static char *Lastleft;
    static int Lastcnt;
    int curcnt, curindex, doneline, x;

    cacheindex = Cacheindex;
    curpos = Readbuf;
    readindex = Readindex;
    if (cacheindex) {
        possess(ReadBuf1);
	wait_for(ReadBuf1, TO_BE,0);
	release(ReadBuf1);
	curpos += MAXCHUNK/2;
	readindex += RINDEXSIZE;
    } else {
        possess(ReadBuf0);
	wait_for(ReadBuf0, TO_BE,0);
	release(ReadBuf0);
    }
    readbuf = curpos;
    curcnt = 0;
    Linecount = 0;
    *mybuf = readbuf;
    *myindex = readindex;
    if (Lastcnt) {
        memmove(curpos,Lastleft,Lastcnt);
	curcnt = Lastcnt;
	curpos += Lastcnt;
	Lastcnt = 0;
	Lastleft = NULL;
    }
    curindex = 0;
    x = 0;
    while (!feof(fi)) {
	x = fread(curpos,1,(MAXCHUNK/2)-curcnt-1,fi);
	if (x >0) {
	    f = findeol(curpos,x-1);
	    if (f) break;
	} else
	   x = 0;
    }
    curpos = readbuf;
    curcnt += x;

    while (curindex < curcnt) {
	readindex[Linecount].offset = curindex;
	len = 0;
	doneline = 0;
	f = findeol(&curpos[curindex],curcnt-curindex-1);
	if (f) {
	    doneline = 1;
	    rlen = len = f - &curpos[curindex];
	    if (len > 0 && f[-1] == '\r') {
	        f[-1] = '\n';
		rlen--;
	    }
	    if (rlen < 0) rlen = 0;
	    readindex[Linecount].len = rlen;
	    curpos[curindex+rlen] = '\n';
	    curindex += len + 1;
	} else {
	    if (feof(fi)) {
	        curpos[curcnt] = '\n';
		rlen = len = (curcnt - curindex);
		if (rlen < 0) rlen = 0;
		if (rlen > 0 && curpos[curindex+rlen-1] == '\n') rlen--;
		if (rlen > 0 && curpos[curindex+rlen-1] == '\r') rlen--;
		if (rlen < 0) rlen = 0;
		readindex[Linecount].len = rlen;
		if (rlen < MAXLINE) {Linecount++; doneline = 1;}
		break;
	    }
	    Lastleft = &curpos[curindex];
	    Lastcnt = curcnt - curindex;
	    if (Lastcnt >= MAXLINE) {
		Lastcnt = 0;
	    }
	    break;
	}
	if (len >= MAXLINE) continue;
	if (doneline) {
	    if (++Linecount >= RINDEXSIZE) {
	        if (curindex < curcnt) {
		    Lastleft = &curpos[curindex];
		    Lastcnt = curcnt - curindex;
		}
		break;
	    }
	}
    }
    Cacheindex ^= 1;
    return(Linecount);
}



/*
 * heapcmp is used to compare two values on the "remove list" heap
 * It puts the lowest value on the top, and sorts files which are
 * at eof to the bottom of the heap
 */
int heapcmp(const void *a, const void *b) {
    struct InHeap *a1 = (struct InHeap *)a;
    struct InHeap *b1 = (struct InHeap *)b;
    if (a1->In->eof || b1->In->eof) {
	if (a1->In->eof && b1->In->eof)
	    return (0);
        if (a1->In->eof) return(1);
	return(-1);
    }
    if (a1->In->curlen == 0 || b1->In->curlen == 0) {
	if (a1->In->curlen < b1->In->curlen) return(1);
	if (a1->In->curlen > b1->In->curlen) return(-1);
	return(0);
    }
    return(mystrcmp(a1->In->curline,b1->In->curline));
}

/*
 * A classic, but still effective.
 * reheap takes an array arranged as a heap, and ensures that the lowest
 * value is always at position 0 in the array.  This permits high
 * performance for the rli2 function, regardless of how many files contain the
 * sorted remove data.  As items are removed from the top of the heap (using
 * getnextline, a single call to reheap will ensure that the "next" higher
 * value is present on the top of the heap.
 */
void reheap(struct InHeap *InH, int cnt)
{
    struct InHeap tmp;
    int child, parent;

    parent = 0;
    while ((child = (parent*2)+1) < cnt) {
        if ((child+1) < cnt && heapcmp(&InH[child],&InH[child+1]) >0)
            child++;
        if (heapcmp(&InH[child],&InH[parent]) < 0) {
            tmp = InH[child];InH[child]=InH[parent];InH[parent]=tmp;
            parent = child;
        } else break;
    }
}

/*
 * getnextline processes an Infiles structure pointer, by
 * 1. getting the next '\n' terminated line from the buffer
 * 2. if there is not enough data in the buffer, moving the
 *    last line, and what is available of the current line, to
 *    the top of the buffer, adjusting counts, and reading the
 *    opened file to fill the buffer.
 * 3. Removing any '\r' immediately proceeding the '\n', and adjusting
 *    the line length.  Note that the length it returns includes the
 *    '\n', so the minimum line length is 1, not 0.  A 0 line
 *    length means that there is no more data, and should also have
 *    the eof flag set.  This is redundant (setting the flag and returning
 *    0 length line), and you should probably just drop the eof flag.
 * 4. If Dedupe is set, this also skips (and counts) duplicate lines.
 * 5. This also checks file order.  If lines are not in lexically sorted
 *    order, then the program will abend, and display the out-of-order
 *    lines and line numbers.
 * 6. If a line appears which is > half the buffer size (more or less),
 *    then the program abends, and the user is encouraged to use a larger
 *    buffer.
 */
void getnextline(struct Infiles *infile) {
    char *lastline,*eol;
    int lastlen, offset, len, res;
    do {
	if (infile->curpos >= infile->end && infile->eof) {
	    infile->curlen = 0;
	    return;
	}
	lastline = infile->curline;
	lastlen = infile->curlen;
	infile->curline = &infile->Buffer[infile->curpos];
	eol = findeol(infile->curline,infile->end - infile->curpos);
	if (!eol) { /* Can't find eol? */
	    offset = lastline - infile->Buffer;
	    len = &infile->Buffer[infile->end]-lastline;
	    memmove(infile->Buffer,lastline,len);
	    lastline -= offset;
	    infile->curline -= offset;
	    infile->curpos -= offset;
	    infile->end -= offset;
	    len = fread(&infile->Buffer[infile->end],1,infile->size-infile->end,infile->fi);
	    infile->end += len;
	    infile->Buffer[infile->end] = '\n';
	    if (len == 0)
		infile->eof = feof(infile->fi);
	    eol = findeol(infile->curline,infile->end - infile->curpos);
	    if (!eol) {
		if (infile->end >= infile->curpos)
		    eol = &infile->Buffer[infile->end];
		else
		    eol = infile->curline;
	    }
	}
	infile->curlen = eol - infile->curline +1;
	if (infile->curpos >= infile->end) {
	    infile->curlen = 0;
	    infile->eof = feof(infile->fi);
	    return;
	}
	infile->line++;
	infile->curpos +=  infile->curlen;
	if (eol > infile->curline && eol[-1] == '\r') {
	    eol[-1] = '\n'; infile->curlen--;
	}
	if (infile->curlen == 0)
	    infile->eof = feof(infile->fi);
	else {
	    if (infile->curlen > ((infile->size/2)-5)) {
		fprintf(stderr,"Line %"PRIu64" in \"%s\" is too long at %"PRIu64"\n",infile->line,infile->fn,infile->curlen);
		fprintf(stderr,"Increase the memory available using -M\n");
		fprintf(stderr,"Memory is set to %"PRIu64", so try -M %"PRIu64"\n",MaxMem, 2*MaxMem);
		exit(1);
	    }
	    res = mylstrcmp(lastline,infile->curline);
	    if (res > 0) {
		fprintf(stderr,"File \"%s\" is not in sorted order at line %"PRIu64"\n",infile->fn,infile->line);
		fprintf(stderr,"Line %"PRIu64": ",infile->line-1);prstr(lastline,lastlen);
		fprintf(stderr,"Line %"PRIu64": ",infile->line);prstr(infile->curline,infile->curlen);
		exit(1);
	    }
	    if (res ==0) {
		infile->dup++;
	    } else
		infile->unique++;
	    if (Dedupe == 0 || res != 0) return;
	}
    } while (1);
}







int rulecomp(const void *a, const void *b) {
   struct RuleSort *a1, *b1;
   a1 = (struct RuleSort *)a;
   b1 = (struct RuleSort *)b;
   if (a1->count > b1->count) return(-1);
   if (a1->count < b1->count) return(1);
   return(0);
}



  


/*
 * xorshift32 - fast, portable PRNG for Phase 2 chain generation
 */
static inline uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return *state = x;
}

/*
 * build_rule_catalog - enumerate all single hashcat rules for discovery
 *
 * Generates ~3000-5000 rules covering:
 *   - No-arg transforms (l u c C t r d f { } [ ] k K q E h H)
 *   - Position-based ops with positions 0-9 (T D ' z Z p y Y L R + - . ,)
 *   - Character-based ops with printable ASCII ($  ^ @ e)
 *   - Position+char ops (i o) with pos 0-9 x printable chars
 *   - Common substitutions (s) - leet speak + case swaps
 *   - Position+position ops (x O *) with pos 0-9 x pos 0-9
 *
 * Skip reject rules (/ ! ( ) = % _ < > Q) and memory rules (M 4 6 X)
 */
static void build_rule_catalog(void) {
    int alloc = 8192;
    int count = 0;
    char **cat;
    char buf[16];
    int i, j, k;
    const char *positions = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *noarg = "lucCtrdf{}[]kKqEhH";
    const char *posops = "TD'zZpyYLR+-.," ;
    const char *charops = "$^@e";
    const char *poscharops = "io";
    const char *posposops = "xO*";

    cat = malloc(alloc * sizeof(char *));
    if (!cat) {
	fprintf(stderr,"Out of memory building rule catalog\n");
	exit(1);
    }

    /* No-arg rules */
    for (i = 0; noarg[i]; i++) {
	buf[0] = noarg[i]; buf[1] = 0;
	cat[count++] = strdup(buf);
    }

    /* Position-based rules: op + position 0-9 */
    for (i = 0; posops[i]; i++) {
	for (j = 0; positions[j]; j++) {
	    buf[0] = posops[i]; buf[1] = positions[j]; buf[2] = 0;
	    cat[count++] = strdup(buf);
	}
    }

    /* Character-based rules: op + printable char (0x21-0x7e) */
    for (i = 0; charops[i]; i++) {
	for (j = 0x21; j <= 0x7e; j++) {
	    buf[0] = charops[i]; buf[1] = (char)j; buf[2] = 0;
	    cat[count++] = strdup(buf);
	}
    }

    /* Position+char rules: op + position + printable char */
    for (i = 0; poscharops[i]; i++) {
	for (j = 0; positions[j]; j++) {
	    for (k = 0x21; k <= 0x7e; k++) {
		if (count >= alloc - 1) {
		    alloc *= 2;
		    cat = realloc(cat, alloc * sizeof(char *));
		    if (!cat) {
			fprintf(stderr,"Out of memory building rule catalog\n");
			exit(1);
		    }
		}
		buf[0] = poscharops[i]; buf[1] = positions[j];
		buf[2] = (char)k; buf[3] = 0;
		cat[count++] = strdup(buf);
	    }
	}
    }

    /* Position+position rules: op + pos + pos */
    for (i = 0; posposops[i]; i++) {
	for (j = 0; positions[j]; j++) {
	    for (k = 0; positions[k]; k++) {
		if (count >= alloc - 1) {
		    alloc *= 2;
		    cat = realloc(cat, alloc * sizeof(char *));
		    if (!cat) {
			fprintf(stderr,"Out of memory building rule catalog\n");
			exit(1);
		    }
		}
		buf[0] = posposops[i]; buf[1] = positions[j];
		buf[2] = positions[k]; buf[3] = 0;
		cat[count++] = strdup(buf);
	    }
	}
    }

    /* Substitution rules (sXY): all letter/digit X → printable Y */
    {
	const char *subchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int si, sj;
	for (si = 0; subchars[si]; si++) {
	    for (sj = 0x21; sj <= 0x7e; sj++) {
		if (sj == subchars[si]) continue; /* skip identity */
		if (count >= alloc - 1) {
		    alloc *= 2;
		    cat = realloc(cat, alloc * sizeof(char *));
		    if (!cat) {
			fprintf(stderr,"Out of memory building rule catalog\n");
			exit(1);
		    }
		}
		buf[0] = 's'; buf[1] = subchars[si]; buf[2] = (char)sj; buf[3] = 0;
		cat[count++] = strdup(buf);
	    }
	}
    }

    CatalogRules = cat;
    CatalogCount = count;
}


/*
 * phase1_worker - Phase 1 thread function
 *
 * Each thread owns a slice of the base wordlist and iterates ALL catalog
 * rules against it.  No per-rule synchronization barrier — each worker
 * runs independently for the entire phase, keeping its word slice hot
 * in cache while the small packed rule stays in L1.
 *
 * Per-rule hit counts are accumulated in a thread-local array and
 * aggregated by the main thread after join.
 */
MDXALIGN void phase1_worker(void *arg) {
    struct Phase1Arg *pa = (struct Phase1Arg *)arg;
    char *outline, *workline, *workline2;
    char *key, *eol, *s, *d, *ruleword;
    int64_t llen, wlen, tlen;
    uint64_t index;
    int r, delflag, x;
    Word_t *PV;

    outline = malloc(MAXLINE+16);
    workline = malloc(MAXLINE+16);
    workline2 = malloc(MAXLINE+16);
    pa->hits = calloc(CatalogCount, sizeof(uint64_t));
    pa->total_hits = 0;

    if (!outline || !workline || !workline2 || !pa->hits) {
	fprintf(stderr, "Out of memory in phase1_worker\n");
	return;
    }

    for (r = 0; r < CatalogCount; r++) {
	if (!CatalogValid[r]) continue;

	if (pa->id == 0 && (r % 100) == 0) {
	    fprintf(stderr, "\r  %s/", commify(r));
	    fprintf(stderr, "%s rules tested...", commify(CatalogCount));
	}

	for (index = pa->start; index < pa->end; index++) {
	    delflag = (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
	    if (delflag) continue;
	    key = (char *)((uint64_t)Sortlist[index] & 0x7fffffffffffffffL);
	    eol = findeol(key, Fileend - key);
	    if (!eol) eol = Fileend;
	    if (eol > key && eol[-1] == '\r') eol--;
	    wlen = llen = eol - key;
	    if (wlen > 5 && strncmp(key, "$HEX[", 5) == 0) {
		wlen = llen = get32(key+5, (unsigned char *)workline, wlen-6);
		key = workline;
		key[wlen] = 0;
	    }
	    tlen = applyrule(key, outline, llen, PackedCatalog[r]);
	    if (tlen <= 0) continue;
	    if ((wlen == tlen) && strncmp(key, outline, wlen) == 0)
		continue;

	    /* HEX encode if needed */
	    ruleword = outline;
	    delflag = 0;
	    for (x = 0, s = outline; NoHEX == 0 && x < tlen; s++, x++) {
		if ((signed char)(*s) < '!' || *s == ':') { delflag = 1; break; }
	    }
	    if (delflag) {
		/* HEX output is 5 + tlen*2 + 2 bytes; skip if it won't fit */
		if (tlen * 2 + 7 > MAXLINE + 16) continue;
		memcpy(workline2, "$HEX[", 5);
		d = workline2 + 5;
		for (x = 0, s = outline; x < tlen; x++, s++, d += 2)
		    *(unsigned short *)d = *(unsigned short *)&hexlut[((unsigned char)*s)*2];
		*d++ = ']'; *d = 0;
		tlen = d - workline2;
		ruleword = workline2;
	    }

	    JSLG(PV, Match, (uint8_t *)ruleword);
	    if (PV) {
		pa->hits[r]++;
		pa->total_hits++;
	    }
	}
    }

    free(outline); free(workline); free(workline2);
}


/*
 * discover_worker - Phase 2 thread function
 *
 * Each thread independently generates random chains of 2-MaxDepth rules,
 * tests them against all base words, and records matches.
 */
MDXALIGN void discover_worker(void *arg) {
    struct DiscoverArg *da = (struct DiscoverArg *)arg;
    uint32_t seed = da->seed;
    int64_t iters = da->iters;
    int id = da->id;
    char *chainbuf, *packedbuf, *outline, *workline, *workline2;
    char *key, *eol, *s, *d, *ruleword, *rule;
    int64_t llen, wlen, tlen;
    uint64_t index, chain_hits;
    int depth, r, delflag, x;
    Word_t *PV;
    int64_t i;
    int do_sample;
    uint32_t sample_thresh, seed2;
    int ralloc;

    /* Precompute sampling threshold from percentage */
    do_sample = (SampleRate < 100.0);
    if (do_sample)
	sample_thresh = (uint32_t)(SampleRate / 100.0 * 4294967296.0);
    else
	sample_thresh = 0xFFFFFFFFU;

    /* Thread-local results array */
    ralloc = 4096;
    da->results = malloc(ralloc * sizeof(struct ChainResult));
    da->nresults = 0;
    da->alloc_results = ralloc;

    chainbuf = malloc(MAXRULELINE+16);
    packedbuf = malloc(MAXRULELINE+16);
    outline = malloc(MAXLINE+16);
    workline = malloc(MAXLINE+16);
    workline2 = malloc(MAXLINE+16);
    if (!chainbuf || !packedbuf || !outline || !workline || !workline2 || !da->results) {
	fprintf(stderr,"Out of memory in discover_worker\n");
	return;
    }

    for (i = 0; i < iters; i++) {
	if (id == 0 && (i % 1000) == 0 && i > 0)
	    fprintf(stderr,"\r  Phase 2: %s iterations...",
		commify((uint64_t)i * (uint64_t)Maxt));

	/* Generate random chain of depth 2..MaxDepth */
	depth = 2;
	if (MaxDepth > 2)
	    depth = 2 + (int)(xorshift32(&seed) % (unsigned)(MaxDepth - 1));

	d = chainbuf;
	delflag = 0;
	for (r = 0; r < depth; r++) {
	    int rlen;
	    if (r > 0) *d++ = ' ';
	    if (HotRuleCount > 0 && (xorshift32(&seed) % 100) < 60)
		rule = HotRuleList[xorshift32(&seed) % (unsigned)HotRuleCount];
	    else
		rule = CatalogRules[xorshift32(&seed) % (unsigned)CatalogCount];
	    rlen = strlen(rule);
	    if (d - chainbuf + rlen + 2 > MAXRULELINE) { delflag = 1; break; }
	    memcpy(d, rule, rlen);
	    d += rlen;
	}
	*d = 0;
	if (delflag) continue;

	/* Bloom dedup: skip chains already tested */
	{
	    uint64_t bh1 = XXH3_64bits(chainbuf, strlen(chainbuf));
	    uint64_t bh2 = bh1 >> 17 ^ bh1;
	    uint64_t dup = Bloomset(bh1 & BLOOMMASK);
	    dup |= Bloomset(bh2 & BLOOMMASK);
	    if (dup) continue;
	}

	/* Pack and validate */
	strncpy(packedbuf, chainbuf, MAXRULELINE-1);
	packedbuf[MAXRULELINE-1] = 0;
	if (packrules(packedbuf)) continue;
	strncpy(workline, "Password", 9);
	if (applyrule(workline, outline, 8, packedbuf) == -3) continue;

	/* Test chain against base words, count hits */
	chain_hits = 0;
	seed2 = seed;
	for (index = 0; index < Line_global; index++) {
	    if (do_sample && xorshift32(&seed2) > sample_thresh) continue;
	    delflag = (((uint64_t)Sortlist[index]) & 0x8000000000000000L) ? 1 : 0;
	    if (delflag) continue;
	    key = (char *)((uint64_t)Sortlist[index] & 0x7fffffffffffffffL);
	    eol = findeol(key, Fileend - key);
	    if (!eol) eol = Fileend;
	    if (eol > key && eol[-1] == '\r') eol--;
	    wlen = llen = eol - key;
	    if (wlen > 5 && strncmp(key, "$HEX[", 5) == 0) {
		wlen = llen = get32(key+5, (unsigned char *)workline, wlen-6);
		key = workline;
		key[wlen] = 0;
	    }
	    tlen = applyrule(key, outline, llen, packedbuf);
	    if (tlen <= 0) continue;
	    if ((wlen == tlen) && strncmp(key, outline, wlen) == 0) continue;

	    ruleword = outline;
	    delflag = 0;
	    for (x = 0, s = outline; NoHEX == 0 && x < tlen; s++, x++) {
		if ((signed char)(*s) < '!' || *s == ':') { delflag = 1; break; }
	    }
	    if (delflag) {
		/* HEX output is 5 + tlen*2 + 2 bytes; skip if it won't fit */
		if (tlen * 2 + 7 > MAXLINE + 16) continue;
		memcpy(workline2, "$HEX[", 5);
		d = workline2 + 5;
		for (x = 0, s = outline; x < tlen; x++, s++, d += 2)
		    *(unsigned short *)d = *(unsigned short *)&hexlut[((unsigned char)*s)*2];
		*d++ = ']'; *d = 0;
		ruleword = workline2;
	    }

	    JSLG(PV, Match, (uint8_t *)ruleword);
	    if (PV) chain_hits++;
	}

	/* Record chain if it meets minimum hit threshold */
	if (chain_hits > 0 && (int)chain_hits >= MinHits) {
	    if (da->nresults >= da->alloc_results) {
		da->alloc_results *= 2;
		da->results = realloc(da->results,
		    da->alloc_results * sizeof(struct ChainResult));
		if (!da->results) {
		    fprintf(stderr, "Out of memory in discover_worker results\n");
		    break;
		}
	    }
	    da->results[da->nresults].chain = strdup(chainbuf);
	    da->results[da->nresults].hits = chain_hits;
	    da->nresults++;
	    __sync_add_and_fetch(&Matchhits, chain_hits);
	    __sync_add_and_fetch(&Rulehits, 1);
	}
    }

    free(chainbuf); free(packedbuf); free(outline);
    free(workline); free(workline2);
}


/*
 * run_discovery - orchestrate Phase 1 (exhaustive) and Phase 2 (random chains)
 */
static void run_discovery(uint64_t Line, char *ruleline, char *ruleline1,
			  char *workline, char *outline) {
    int i, x;
    uint64_t work, curpos;
    struct JOB *job;
    Word_t *PV;
    struct timespec starttime, curtime;
    double wtime;
    uint64_t p1_rulehits, p1_matchhits;

    build_rule_catalog();
    fprintf(stderr, "Rule catalog: %s single rules\n", commify(CatalogCount));

    /* Pre-pack and validate all catalog rules (main thread, once) */
    PackedCatalog = malloc(CatalogCount * sizeof(char *));
    CatalogValid = calloc(CatalogCount, sizeof(int));
    if (!PackedCatalog || !CatalogValid) {
	fprintf(stderr, "Out of memory for packed catalog\n");
	exit(1);
    }
    {
	int valid = 0;
	for (i = 0; i < CatalogCount; i++) {
	    PackedCatalog[i] = malloc(MAXRULELINE+16);
	    if (!PackedCatalog[i]) {
		fprintf(stderr, "Out of memory packing rule %d\n", i);
		exit(1);
	    }
	    strncpy(PackedCatalog[i], CatalogRules[i], MAXRULELINE-1);
	    PackedCatalog[i][MAXRULELINE-1] = 0;
	    if (packrules(PackedCatalog[i])) continue;
	    strncpy(workline, "Password", 9);
	    if (applyrule(workline, outline, 8, PackedCatalog[i]) == -3) continue;
	    CatalogValid[i] = 1;
	    valid++;
	}
	fprintf(stderr, "  %d valid rules after packing\n", valid);
    }

    /* Terminate procjob workers before Phase 1 (they served line counting) */
    if (Workthread) {
	possess(FreeWaiting);
	wait_for(FreeWaiting, NOT_TO_BE, 0);
	job = FreeHead;
	FreeHead = job->next;
	if (FreeHead == NULL) FreeTail = &FreeHead;
	twist(FreeWaiting, BY, -1);
	job->next = NULL;
	job->func = JOB_DONE;
	possess(WorkWaiting);
	*WorkTail = job;
	WorkTail = &(job->next);
	twist(WorkWaiting, BY, +1);
	join_all();
	Workthread = 0;
    }

    /* Phase 1: Each worker owns a wordlist slice, iterates ALL rules */
    fprintf(stderr, "Phase 1: Testing all single rules against %s base words",
	    commify(Line));
    fprintf(stderr, " with %d threads...\n", Maxt);
    current_utc_time(&starttime);

    {
	struct Phase1Arg *p1args;
	uint64_t chunk;
	int r;

	p1args = calloc(Maxt, sizeof(struct Phase1Arg));
	if (!p1args) {
	    fprintf(stderr, "Out of memory for Phase 1 args\n");
	    exit(1);
	}
	chunk = Line / Maxt;
	for (i = 0; i < Maxt; i++) {
	    p1args[i].id = i;
	    p1args[i].start = (uint64_t)i * chunk;
	    p1args[i].end = (i == Maxt - 1) ? Line : (uint64_t)(i + 1) * chunk;
	    launch(phase1_worker, &p1args[i]);
	}
	join_all();

	/* Aggregate per-thread hit counts into MRule */
	for (i = 0; i < Maxt; i++) {
	    Matchhits += p1args[i].total_hits;
	    if (!p1args[i].hits) continue;
	    for (r = 0; r < CatalogCount; r++) {
		if (p1args[i].hits[r] > 0) {
		    JSLI(PV, MRule, (uint8_t *)CatalogRules[r]);
		    if (PV) *PV += p1args[i].hits[r];
		}
	    }
	    free(p1args[i].hits);
	}
	/* Count unique rules with hits */
	ruleline[0] = 0;
	JSLF(PV, MRule, (uint8_t *)ruleline);
	while (PV) { Rulehits++; JSLN(PV, MRule, (uint8_t *)ruleline); }

	free(p1args);
    }

    current_utc_time(&curtime);
    wtime = (double)curtime.tv_sec + (double)(curtime.tv_nsec) / 1000000000.0;
    wtime -= (double)starttime.tv_sec + (double)(starttime.tv_nsec) / 1000000000.0;
    fprintf(stderr, "\rPhase 1 complete: %s rules matched",
	    commify(Rulehits));
    fprintf(stderr, " %s times in %.4f seconds\n",
	    commify(Matchhits), wtime);

    /* Collect hot rules from MRule for Phase 2 seeding */
    HotRuleCount = 0;
    HotRuleList = calloc(Rulehits + 1, sizeof(char *));
    if (!HotRuleList) {
	fprintf(stderr, "Out of memory for hot rule list\n");
	exit(1);
    }

    ruleline[0] = 0;
    JSLF(PV, MRule, (uint8_t *)ruleline);
    while (PV) {
	HotRuleList[HotRuleCount++] = strdup(ruleline);
	JSLN(PV, MRule, (uint8_t *)ruleline);
    }
    fprintf(stderr, "Phase 1: %d hot rules (with hits) collected\n", HotRuleCount);

    p1_rulehits = Rulehits;
    p1_matchhits = Matchhits;

    /* Phase 2: Random chain generation */
    if (MaxDepth > 1 && MaxIter > 0) {
	struct DiscoverArg *args;
	int j;

	/* Allocate Bloom filter for Phase 2 chain dedup */
	if (!Bloom) {
	    Bloom = calloc(BLOOMSIZE/64 + 1, sizeof(uint64_t));
	    if (!Bloom) {
		fprintf(stderr, "Can't allocate Bloom filter for Phase 2\n");
		exit(1);
	    }
	}

	/* Auto-calculate sample rate if not specified (-S).
	 * Target: Phase 2 completes in ~90 seconds.
	 * cost_per_rule from Phase 1, empirical 40x multiplier for
	 * multi-rule chains with match-rate overhead.
	 */
	if (SampleRate < 0.0) {
	    double cost_per_rule = wtime / (double)CatalogCount;
	    double target_secs = 90.0;
	    if (cost_per_rule > 0.0) {
		SampleRate = target_secs * (double)Maxt * 100.0
			   / ((double)MaxIter * 40.0 * cost_per_rule);
		if (SampleRate > 100.0) SampleRate = 100.0;
		if (SampleRate < 0.001) SampleRate = 0.001;
	    } else {
		SampleRate = 100.0;
	    }
	    fprintf(stderr, "Auto sample rate: %.4f%% (targeting ~%.0fs Phase 2)\n",
		    SampleRate, target_secs);
	}

	fprintf(stderr, "Phase 2: Testing %s random chains (depth 2-%d)",
		commify(MaxIter), MaxDepth);
	if (SampleRate < 100.0)
	    fprintf(stderr, ", %.4f%% sample", SampleRate);
	fprintf(stderr, ", %d threads...\n", Maxt);
	current_utc_time(&starttime);

	args = malloc(Maxt * sizeof(struct DiscoverArg));
	if (!args) {
	    fprintf(stderr, "Out of memory for Phase 2 args\n");
	    exit(1);
	}
	for (i = 0; i < Maxt; i++) {
	    args[i].id = i;
	    args[i].iters = MaxIter / Maxt;
	    if (i == 0) args[i].iters += MaxIter % Maxt;
	    args[i].seed = (uint32_t)(time(NULL) ^ ((unsigned)i * 2654435761U));
	    if (args[i].seed == 0) args[i].seed = 1;
	    launch(discover_worker, &args[i]);
	}
	x = join_all();

	current_utc_time(&curtime);
	wtime = (double)curtime.tv_sec + (double)(curtime.tv_nsec) / 1000000000.0;
	wtime -= (double)starttime.tv_sec + (double)(starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr, "\rPhase 2 complete: %s new rules",
		commify(Rulehits - p1_rulehits));
	fprintf(stderr, ", %s new matches in %.4f seconds\n",
		commify(Matchhits - p1_matchhits), wtime);

	/* Merge Phase 2 thread results into MRule */
	for (i = 0; i < Maxt; i++) {
	    if (!args[i].results) continue;
	    for (j = 0; j < args[i].nresults; j++) {
		JSLI(PV, MRule, (uint8_t *)args[i].results[j].chain);
		if (PV) {
		    if (*PV == 0)
			*PV = args[i].results[j].hits;
		    else
			*PV += args[i].results[j].hits;
		}
		free(args[i].results[j].chain);
	    }
	    free(args[i].results);
	}
	free(args);
    }

    /* Final output: all rules sorted by hit count (most valuable first) */
    {
	uint64_t total_rules = 0;
	uint64_t curpos;

	ruleline[0] = 0;
	JSLF(PV, MRule, (uint8_t *)ruleline);
	while (PV) { total_rules++; JSLN(PV, MRule, (uint8_t *)ruleline); }

	FinalRules = calloc(total_rules + 1, sizeof(struct RuleSort));
	if (!FinalRules) {
	    fprintf(stderr, "No memory for final rule sort\n");
	    exit(1);
	}
	ruleline[0] = 0;
	curpos = 0;
	JSLF(PV, MRule, (uint8_t *)ruleline);
	while (PV) {
	    FinalRules[curpos].count = *PV;
	    FinalRules[curpos].rule = strdup(ruleline);
	    curpos++;
	    JSLN(PV, MRule, (uint8_t *)ruleline);
	}
	qsort(FinalRules, total_rules, sizeof(struct RuleSort), rulecomp);

	for (curpos = 0; curpos < total_rules; curpos++)
	    fprintf(Fo, "%s\n", FinalRules[curpos].rule);
	fflush(Fo);

	fprintf(stderr, "\nDiscovery complete: %s rules",
		commify(total_rules));
	fprintf(stderr, ", %s total matches, sorted by hit count\n",
		commify(Matchhits));
	if (total_rules > 0) {
	    fprintf(stderr, "  Top rules:\n");
	    for (curpos = 0; curpos < total_rules && curpos < 10; curpos++)
		fprintf(stderr, "    %7llu  %s\n",
		    (long long unsigned int)FinalRules[curpos].count,
		    FinalRules[curpos].rule);
	}
    }
}


/* The mainline code.  Yeah, it's ugly, dresses poorly, and smells funny.
 *
 * But it's pretty fast.
 */

int main(int argc, char **argv) {
    struct timespec starttime,curtime, inittime;
    double wtime;
    int64_t llen, wlen, wcnt;
    uint64_t Line, Estline,  RC, Totrem;
    uint64_t work,curpos, thisnum, Currem, mask, matchlist;
    uint64_t matchunique;
    struct Linelist *cur, *next;
    int ch,  x, y, progress, Hidebit, last, forkelem;
    int curfile;
    int ErrCheck;
    int curline, numline, Linecount, dbindex, RuleFileCount;
    char *readbuf;
    struct LineInfo *readindex;
    FILE *fin, *fi, *vmfile, *rulefile, *statfile;
    uint64_t crc, memsize, memscale;
    off_t filesize, readsize;
    int HashOpt=0;
    struct JOB *job;
    struct WorkUnit *wu, *wulast;
    struct stat sb1;
    char *linein, *newline, **sorted, *thisline, *eol;
    char *ruleline,*ruleline1,*workline, *work2line, *outline, *rulefn;
    char *s, *d;
    char *qopts;
    Pvoid_t RuleFiles;
    Word_t *PV;
    char **RuleFileList;
#ifndef _AIX
    struct option longopt[] = {
	{NULL,0,NULL,0}
    };
#endif
    struct stat statb;

    NoHEX = 0;
    statfile = NULL;
    Linefile = NULL;
    RuleFileCount = 0;
    RuleFiles = NULL;
    Match = NULL;
    Matchhits = Rulehits = 0;
    MRule = NULL;
    Matchtot = matchlist = 0;
    rulefn = NULL;
    Fo = stdout;
    qopts = NULL;
    MaxMem = MAXCHUNK;
    ErrCheck = 1;
    DropCR = 1;
    Dedupe = 1;
    DoDebug = 0;
    SortOut = 0;
    LenMatch = 0;
    Maxdepth_global = 0;
    Workthread = 0;
    last = 99;
    mask = 0xffff;

    ruleline = malloc(MAXRULELINE+16);
    ruleline1 = malloc(MAXRULELINE+16);
    rulefn = malloc(MAXRULELINE+16);
    workline = malloc(MAXLINE+16);
    work2line = malloc(MAXLINE+16);
    outline = malloc((MAXLINE*3)+16);
    RuleFileList = calloc(MAXRULEFILES+10,sizeof(char *));
    if (!RuleFileList || !rulefn || !ruleline || !ruleline1 || 
	!work2line || !workline || !outline) {
       fprintf(stderr,"Can't allocate memory for rules!\n");
       perror("rules:");
       exit(1);
    }
    ProcMode = Hidebit =  DoCommon = 0;
    Maxt = get_nprocs();
    current_utc_time(&starttime);
    current_utc_time(&inittime);
#ifdef _AIX
    while ((ch = getopt(argc, argv, "?hvVxr:t:p:M:m:o:l:s:B:G:D:N:S:H:")) != -1) {
#else
    while ((ch = getopt_long(argc, argv, "?hvVxr:t:p:M:m:o:l:s:B:G:D:N:S:H:",longopt,NULL)) != -1) {
#endif
	switch(ch) {
	    case '?':
	    case 'h':
errexit:
                linein = Version;
                while (*linein++ != ' ');
                while (*linein++ != ' ');
                fprintf(stderr,"\nprocrule version: %s\n\n",linein);
		fprintf(stderr,"procrule [options] wordlist\n");
		fprintf(stderr,"\tOnly one wordlist can be specified.  Multiple rule files can be used.\n");
		fprintf(stderr,"\n\tstdin and stdout can be used in the place of any filename\n");
		fprintf(stderr,"-h\t\tThis help message\n");
		fprintf(stderr,"-t [num]\tMaximum number of threads to use.\n");
		fprintf(stderr,"-r [file/pipe]\tRead rules from this file or pipe.\n");
		fprintf(stderr,"-m [file]\tList of result words to match against.\n\t\tMay be specified multiple times.\n\t\tNo match file means generate all candidate words\n");
		fprintf(stderr,"-o [file/pipe]\tRedirects output from stdout to file/pipe\n");
		fprintf(stderr,"-l [file/pipe]\tLine match with in word/rule/outword\n");
		fprintf(stderr,"-s [file/pipe]\tOutput rule match statistics to file\n");
		fprintf(stderr,"-v\t\tVerbose mode.  Use multiple times for more output\n");
		fprintf(stderr,"-x\t\tDisable $HEX[] encoding on output\n");
		fprintf(stderr,"-G [file]\tDiscovery mode: find rules that transform base words into targets\n");
		fprintf(stderr,"-D [num]\tMax chain depth for discovery (default: 3, 1=single only)\n");
		fprintf(stderr,"-N [num]\tPhase 2 random chain iterations (default: 10000000)\n");
		fprintf(stderr,"-S [rate]\tPhase 2 word sample rate in %% (e.g. 1.0 = 1%%, default: auto)\n");
		fprintf(stderr,"-H [num]\tMinimum hit count to keep a Phase 2 rule (default: 0)\n");

		exit(1);
		break;

	    case 'V':
		printf("procrule: %s\n", Version);
		exit(0);

	    case 'B':
		Bench = atol(optarg);
		if (Bench <=0) {
		   fprintf(stderr,"Invalid benchmark iteration: %s\n", optarg);
		   exit(1);
		}
	    case 's':
	        if (strncmp(optarg,"stdout",6) == 0) {
 		    statfile = stdout;
		    break;
		}
	        if (strncmp(optarg,"stderr",6) == 0) {
 		    statfile = stderr;
		    break;
		}
		statfile = fopen(optarg,"wb");
		if (!statfile) {
		    fprintf(stderr,"Can't open stat output file: ");
		    perror(optarg);
		    exit(1);
		}
		break;

	    case 'l':
	        if (strncmp(optarg,"stdout",6) == 0)
		    Linefile = stdout;
		else {
		    Linefile = fopen(optarg,"wb");
		    if (!Linefile) {
		        fprintf(stderr,"Can't open line output file:");
			perror(optarg);
			exit(1);
		    }
		}
		break;
	    case 'x':
		NoHEX = 1;
		break;
	    case 'm':
	    	fi = fopen(optarg,"rb");
		if (!fi) {
		    fprintf(stderr,"Can't open match file: ");
		    perror(optarg);
		    goto errexit;
		}
		matchlist = 0;
		matchunique = 0;
		while (fgets(ruleline,MAXRULELINE-10,fi)) {
		    eol = findeol(ruleline,MAXRULELINE-10);
		    if (!eol) eol = ruleline+MAXRULELINE-10;
		    if (eol > (ruleline+1)) {
		        if (eol[-1] == '\r') 
			   *--eol = 0;
			else
			   *eol = 0;
		    }
		    for (x=0,s=ruleline; s < eol; s++) {
		        if ((signed char)(*s) < '!' || *s == ':') {
			    x = 1;
			    break;
			}
		    }
		    if (x) {
		        strncpy(work2line,"$HEX[",5);
			d = work2line+5;
			for (s= ruleline; s < eol; s++) {
			    sprintf(d,"%02x",(*s)&0xff);
			    d += 2;
			}
			*d++ = ']';
			*d = 0;
			JSLI(PV,Match,(uint8_t *)work2line);
		    } else {
			JSLI(PV,Match,(uint8_t *)ruleline);
		    }
		    if (!PV) {
		        fprintf(stderr,"Out of memory reading Match file %s\n",optarg);
			exit(1);
		    }
		    if (*PV == 0) {matchlist++;Matchtot++;matchunique++;}
		    *PV = *PV + 1;
		}
		fclose(fi);
		fprintf(stderr,"File %s had %"PRIu64" lines, %"PRIu64" unique lines\n",optarg,matchlist,matchunique);

		break;



	    case 'o':
	    	if (strncmp(optarg,"stdout",6) ==0) {
		    Fo = stdout;
		} else {
		    Fo = fopen(optarg,"wb");
		    if (!Fo) {
		        fprintf(stderr,"Can't open output:");
			perror(optarg);
		    }
		}
		break;
	    case 'r':
		if (optarg == NULL || strlen(optarg) < 1 || strlen(optarg) > (MAXRULELINE -10)) {
		    fprintf(stderr,"Invalid rule file: %s\n",(optarg)?optarg:"NULL");
		    goto errexit;
		}
		JSLI(PV,RuleFiles,(uint8_t *)optarg);
		if (!PV) {
		    fprintf(stderr,"Out of memory adding rule files.\n");
		    exit(1);
		}
		if (*PV == 0) {
		    RuleFileList[RuleFileCount] = strdup(optarg);
		    if (!RuleFileList[RuleFileCount]) {
		    	fprintf(stderr,"Out of memory adding rule files\n");
			exit(1);
		    }
		    RuleFileCount++;
		    if (RuleFileCount > MAXRULEFILES) {
			fprintf(stderr,"Too many -r arguments\n");
			exit(1);
		    }
		}
		*PV = *PV + 1;
		break;

	    case 'p':
		HashOpt = atoi(optarg);
		if (HashOpt <= 0) {
		    fprintf(stderr,"Hash prime must be positive value\n");
		    exit(1);
		}
	        break;

	    case 'M':
	    	RC = atol(optarg);
		if (strlen(optarg)) {
		    ch = optarg[strlen(optarg)-1];
		    switch (ch) {
		        case 'k':
			case 'K':
			    RC *= 1024L;
			    break;
			case 'm':
			case 'M':
			    RC *= 1024L*1024L;
			    break;
			case 'G':
			case 'g':
			    RC *= 1024L*1024L*1024L;
			    break;
			default:
			    break;
		    }
		}
		if (RC <64*1024) {
		    fprintf(stderr,"%"PRIu64" bytes isn't going to be very effective\nTry using more than 64k\n",RC);
		}
		fprintf(stderr,"Memory for cache set to %"PRIu64" bytes (was %"PRIu64")\n",RC,MaxMem);
		MaxMem = RC;
		linein = malloc(MaxMem);
		if (!linein) {
		    fprintf(stderr,"but allocation for that much failed.  Try using a smaller amount\n");
		    exit(1);
		}
		free(linein);
		break;


	    case 't':
	        x = atoi(optarg);
		if (x < 1 || x > 32768) {
		    fprintf(stderr,"Maximum threads invalid: %d\n",x);
		    exit(1);
		}
		fprintf(stderr,"Maximum number of threads was %d, now %d\n",Maxt,x);
		Maxt = x;
		break;
	    case 'G':
		DiscoverFile = strdup(optarg);
		if (!DiscoverFile) {
		    fprintf(stderr,"Out of memory for -G argument\n");
		    exit(1);
		}
		/* Load target file into Match Judy, same as -m */
		fi = fopen(optarg,"rb");
		if (!fi) {
		    fprintf(stderr,"Can't open discovery target file: ");
		    perror(optarg);
		    goto errexit;
		}
		matchlist = 0;
		matchunique = 0;
		while (fgets(ruleline,MAXRULELINE-10,fi)) {
		    eol = findeol(ruleline,MAXRULELINE-10);
		    if (!eol) eol = ruleline+MAXRULELINE-10;
		    if (eol > (ruleline+1)) {
			if (eol[-1] == '\r')
			   *--eol = 0;
			else
			   *eol = 0;
		    }
		    for (x=0,s=ruleline; s < eol; s++) {
			if ((signed char)(*s) < '!' || *s == ':') {
			    x = 1;
			    break;
			}
		    }
		    if (x) {
			strncpy(work2line,"$HEX[",5);
			d = work2line+5;
			for (s= ruleline; s < eol; s++) {
			    sprintf(d,"%02x",(*s)&0xff);
			    d += 2;
			}
			*d++ = ']';
			*d = 0;
			JSLI(PV,Match,(uint8_t *)work2line);
		    } else {
			JSLI(PV,Match,(uint8_t *)ruleline);
		    }
		    if (!PV) {
			fprintf(stderr,"Out of memory reading target file %s\n",optarg);
			exit(1);
		    }
		    if (*PV == 0) {matchlist++;Matchtot++;matchunique++;}
		    *PV = *PV + 1;
		}
		fclose(fi);
		fprintf(stderr,"Target file %s: %"PRIu64" lines, %"PRIu64" unique\n",optarg,matchlist,matchunique);
		break;

	    case 'D':
		MaxDepth = atoi(optarg);
		if (MaxDepth < 1 || MaxDepth > 10) {
		    fprintf(stderr,"Invalid depth (-D): %s (must be 1-10)\n",optarg);
		    exit(1);
		}
		break;

	    case 'N':
		MaxIter = atol(optarg);
		if (MaxIter < 0) {
		    fprintf(stderr,"Invalid iteration count (-N): %s\n",optarg);
		    exit(1);
		}
		break;

	    case 'S':
		SampleRate = atof(optarg);
		if (SampleRate <= 0.0 || SampleRate > 100.0) {
		    fprintf(stderr,"Invalid sample rate (-S): %s (must be >0.0 and <=100.0)\n",optarg);
		    exit(1);
		}
		break;

	    case 'H':
		MinHits = atoi(optarg);
		if (MinHits < 0) {
		    fprintf(stderr,"Invalid minimum hits (-H): %s\n",optarg);
		    exit(1);
		}
		break;

	    case 'v':
		DoDebug++;
		break;
	}
    }
    argc -= optind;
    argv += optind;

    if (RuleFileCount == 0 && !DiscoverFile) {
	fprintf(stderr,"No rule file(s) (-r) or discovery target (-G) supplied!");
	goto errexit;
    }
    if (argc < 1) {
        fprintf(stderr,"Need at least an input wordlist to process.\n");
	goto errexit;
    }

    Minlen_global = (uint64_t)-1L;
    Maxlen_global = 0;
    Readbuf = malloc(MAXCHUNK+16);
    Readindex = malloc(MAXLINEPERCHUNK*2*sizeof(struct LineInfo)+16);
    Jobs = calloc(Maxt,sizeof(struct JOB));
    WUList = calloc(Maxt,sizeof(struct WorkUnit));
    FreeWaiting = new_lock(Maxt);
    WorkWaiting = new_lock(0);
    WUWaiting = new_lock(0);
    Currem_lock = new_lock(0);
    Common_lock = new_lock(0);
    ReadBuf0 = new_lock(0);
    ReadBuf1 = new_lock(0);
    Rule_lock = new_lock(0);
    if (!Readbuf || !Readindex || !WUList || !Jobs || !FreeWaiting || !WorkWaiting || !WUWaiting || !Currem_lock || !ReadBuf0 || !ReadBuf1 || !Common_lock || !Rule_lock) {
	fprintf(stderr,"Can't allocate space for jobs\n");
	fprintf(stderr,"This means that you don't have enough memory available to even\nstart processing.  Please make more memory available.\n");
	exit(1);
    }
    WorkTail = &WorkHead;
    FreeTail = &FreeHead;
    WUTail = &WUHead;
    last = ((MAXCHUNK)/Maxt)/sizeof(char *);
    y = ((MAXCHUNK)/Maxt);
    if (last < 16 || y < 16) {
	fprintf(stderr,"MAXCHUNK is set too low - please fix\n");
	exit(1);
    }
    WorkUnitSize = last;
    for (work=0,x=0; x<Maxt; x++) {
	*FreeTail = &Jobs[x];
	FreeTail = &(Jobs[x].next);
	WUList[x].Sortlist = (char **)&Readbuf[(x*sizeof(char*))*last];
	WUList[x].ssize = last;
 	WUList[x].wulock = new_lock(0);
	if (!WUList[x].wulock || WUList[x].Sortlist > (char **)(&Readbuf[MAXCHUNK])) {
	    fprintf(stderr,"Can't allocate lock for work unit\n");
	    exit(1);
	}
	Jobs[x].wu = &WUList[x];
    }



    if (strcmp(argv[0],"stdin") == 0) {
	fin = stdin;
#ifdef _WIN32
  setmode(0,O_BINARY);
#endif
    } else
	fin = fopen(argv[0],"rb");
    if (!fin) {
	fprintf(stderr,"Can't open:");
	perror(argv[0]);
	exit(1);
    }

    {
	fprintf(stderr,"Reading \"%s\"...",argv[0]);fflush(stderr);
	if (fstat(fileno(fin),&statb)) {
		fprintf(stderr,"Could not stat input file.  This is probably not good news\n");
		perror(argv[0]);
		exit(1);
	}
	if ((statb.st_mode & S_IFREG)) {
	    filesize = statb.st_size;
	    Fileinmem = malloc(filesize + 16);
	    if (!Fileinmem) {
	        fprintf(stderr,"File \"%s\" claimed to be a regular file of size %"PRIu64"\nbut not enough memory was available.  Make more memory available, or check file.\n",argv[0],filesize);
		exit (1);
	    }
	    readsize = fread(Fileinmem,1,filesize,fin);
	    if (readsize < filesize) {
	        if (readsize < 0) {
		   fprintf(stderr,"Read error on input file.\n");
		   perror(argv[0]);
		   exit(1);
		}
		if (readsize < filesize) { 
		    filesize = readsize;
		}
	    }
	} else {
	    Fileinmem = malloc(MAXCHUNK + 16);
	    filesize = 0;
	}
	Line = 0;

	while (!feof(fin)) {
	    readsize = fread(&Fileinmem[filesize],1,MAXCHUNK,fin);
	    if (readsize <= 0) {
		if (feof(fin) || readsize <0) break;
	    }
	    filesize += readsize;
	    Fileinmem = realloc(Fileinmem,filesize + MAXCHUNK + 16);
	    if (!Fileinmem) {
		fprintf(stderr,"Can't get %"PRIu64" more bytes for read buffer\n",(uint64_t)MAXCHUNK);
		fprintf(stderr,"This means that part (%"PRIu64" bytes) of the input file\nread ok, but that's not the end of the file.\nMake more memory available, or decrease the size of the input file\n",filesize);
		exit(1);
	    }
	}
	current_utc_time(&curtime);
	wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	fprintf(stderr,"%"PRIu64" bytes total in %.4f seconds\n",filesize,wtime);
	current_utc_time(&starttime);

	Fileinmem = realloc(Fileinmem,filesize + 16);
	if (!Fileinmem) {
	    fprintf(stderr,"Could not shrink memory buffer\n");
	    fprintf(stderr,"Probably a bug in the program\n");
	    exit(1);
	}
	fclose(fin);

	Fileinmem[filesize] = '\n';
	Fileend = &Fileinmem[filesize];
	Filesize = filesize;
    }
    fprintf(stderr,"Counting lines...    ");fflush(stderr);

    WorkUnitLine = WorkUnitSize * 8;
    if (WorkUnitLine < Maxt)
	WorkUnitLine = filesize;
    thisline = Fileinmem;
    Estline = filesize / 8;
    if (Estline <10) Estline = 10;

    Sortlist = calloc(Estline,sizeof(char *));
    if (!Sortlist) {
	fprintf(stderr,"Can't allocate %s bytes for sortlist\n",commify(Estline*8));
	fprintf(stderr,"All %"PRIu64" bytes of the input file read ok, but there is\nno memory left to build the sort table.\nMake more memory available, or decrease the size of the input file\n",filesize);
	exit(1);
    }


    launch(filljob,NULL);
    for (curpos = 0; curpos < filesize; ) {
	possess(WUWaiting);
	wait_for(WUWaiting, NOT_TO_BE, 0);
	wulast = NULL;
	for (ch = 0,wu = WUHead; wu; wulast = wu, wu = wu->next) {
	    if (wu->start == curpos) {
		if ((Line+wu->count) >= (Estline-2)) {
		    if (filesize)
			RC = Estline + (((filesize - curpos)*Estline)/filesize);
		    else
			RC = Estline + wu->count;
		    if (RC < (Line+wu->count)) RC = Line+wu->count;
		    if (ProcMode == 2) {
			newline = NULL;
			y = ((RC - Estline)+16) * sizeof(char *);
			while (y > 0) {
			    x = (y > MAXCHUNK) ? MAXCHUNK : y;
			    fwrite(Readbuf,x,1,vmfile);
			    y -= x;
			}
			fflush(vmfile);
			for (x = Estline+16; x < RC+16; x++)
			    fwrite(&newline,8,1,vmfile);
			fflush(vmfile);
			Sortlist = mmap(Sortlist,sizeof(char*)*(RC+16),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,fileno(vmfile),0L);
			if (Sortlist == (char **) -1L) Sortlist = NULL;
		    } else {
			Sortlist = realloc(Sortlist,(RC+16) * sizeof(char *));
		    }
		    Estline = RC;
		    if (!Sortlist) {
			fprintf(stderr,"Could not re-allocate for Sortlist\n");
			fprintf(stderr,"This means we read all %"PRIu64"bytes of the input file\nbut we ran out of memory allocating for the sort list\nMake more memory available, or decrease the size of the input file\n",filesize);
			exit(1);
		    }
		}
		if (wu->count) {
		    memcpy(&Sortlist[Line],wu->Sortlist,wu->count*sizeof(char *));
		    Line += wu->count;
		}
		curpos = wu->end;
		if (wu == WUHead) {
		    WUHead = wu->next;
		} else {
		    if (wulast != NULL) {
			wulast->next = wu->next;
		    }
		}
		if (WUTail == &(wu->next)) {
		   if (wulast == NULL)
			WUTail = &WUHead;
		   else
			WUTail = &(wulast->next);
		}
		wu->next = NULL;
		possess(wu->wulock);
		twist(wu->wulock,BY,-1);
		ch = -1;
		break;
	    }
	}
	if (ch == 0) {
	    last = peek_lock(WUWaiting);
	    wait_for(WUWaiting, NOT_TO_BE,last);
	}
	twist(WUWaiting, BY, ch);
    }
    possess(Common_lock);
    wait_for(Common_lock, TO_BE, 1);
    twist(Common_lock, BY, -1);
    possess(FreeWaiting);
    if (peek_lock(FreeWaiting) != Maxt) {
	fprintf(stderr,"Line count failure - free waiting is %ld\n",peek_lock(FreeWaiting));
	wait_for(FreeWaiting, TO_BE,Maxt);
    }
    release(FreeWaiting);
    if (ProcMode != 2) {
	Sortlist = realloc(Sortlist,(Line+16) * sizeof(char *));
    }
    if (!Sortlist) {
	fprintf(stderr,"Final Sortlist shrink failed\n");
	fprintf(stderr,"This means we read all %"PRIu64" bytes of the input file,\nand were able to create the sortlist for all %"PRIu64" lines we found\nLikely, there is a bug in the program\n",filesize,Line);
	exit(1);
    }
    Sortlist[Line] = NULL;
    current_utc_time(&curtime);
    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
    fprintf(stderr,"%c%c%c%cFound %"PRIu64" line%s in %.4f seconds\n",8,8,8,8,(uint64_t)Line,(Line==1)?"":"s",wtime);
    current_utc_time(&starttime);
    Line_global = Line;

    if (Line) {
	WorkUnitLine =  WorkUnitSize * (filesize/Line);
	if (WorkUnitLine > filesize)
	    WorkUnitLine = filesize;
    }
    RC = (uint64_t)&Fileinmem[0];
    RC |= (uint64_t)&Fileinmem[filesize];
    Hidebit = (RC & (1LL<<63)) ? 0 : 1;
    if (Hidebit == 0) {
	fprintf(stderr,"Can't hide the bit\n");
	exit(1);
    }
    memsize = MAXCHUNK +
	      MAXLINEPERCHUNK*2*sizeof(struct LineInfo)+32;
    if (ProcMode != 2)
       memsize	+=
	      filesize +
	      Line * sizeof(char **);

    if (ProcMode == 0) {
	HashSize = HashMask = 0;
	HashPrime = 513;
	for (x=0; Hashsizes[x].size != 0; x++) {
	    HashPrime = Hashsizes[x].prime;
	    if ((Line*2) < Hashsizes[x].size) break;
	}
	fprintf(stderr,"Optimal HashPrime is %"PRIu64" ",HashPrime);
	HashSize = HashPrime;
	if (HashOpt) {
	    fprintf(stderr,"but user requested %d",HashOpt);
	    HashPrime = HashOpt;
	    HashSize = HashPrime;
	    for (work=1024; work && work != HashOpt; work *= 2);
	    if (work == HashOpt) {
		HashMask = work -1;
		HashSize = work;
		HashPrime = 0;
		fprintf(stderr,"\nRequested value is a power-of-two, HashMask=%"PRIu64"x",HashMask);
	    }
	}
	fprintf(stderr,"\n");

	memsize += sizeof(struct LineList *)*HashSize +
		  (Line*sizeof(struct Linelist));
    }


    for (x=0 ; x < 4; x++) {
       if (memsize < Memscale[x].size) break;
    }
    fprintf(stderr,"Estimated memory required: %s (%.02f%s)\n",
	 commify(memsize),(double)memsize/Memscale[x].scale,
	 Memscale[x].name);


    switch (ProcMode) {
    	case 0:
	    HashLine = calloc(sizeof(struct Linelist *),HashSize);
	    Linel = malloc(sizeof(struct Linelist)*(Line+2));

	    if (!HashLine ||  !Linel) {
		fprintf(stderr,"Can't allocate processing space for lines\n");
		fprintf(stderr,"Make more memory available, or consider using -b option.\n");
		exit(1);
	    }

	    Currem = 0;

	    fprintf(stderr,"Processing input list...     ");fflush(stderr);
	    curpos = (Line / Maxt);
	    if (curpos < Maxt) curpos = Line;
	    for (work = 0; work < Line; work += curpos) {
		possess(FreeWaiting);
		wait_for(FreeWaiting, NOT_TO_BE,0);
		job = FreeHead;
		FreeHead = job->next;
		if (FreeHead == NULL) FreeTail = &FreeHead;
		twist(FreeWaiting, BY, -1);
		job->next = NULL; job->func = JOB_GENHASH; job->start = work;
		if ((work + curpos) > Line )
		    job->end = Line;
		else
		    job->end = work + curpos;
		if (Workthread < Maxt) {
		    launch(procjob,NULL);
		    Workthread++;
		}
		possess(WorkWaiting);
		*WorkTail = job;
		WorkTail = &(job->next);
		twist(WorkWaiting,BY,+1);
	    }
	    possess(FreeWaiting);
	    wait_for(FreeWaiting,TO_BE,Maxt);
	    release(FreeWaiting);

	    current_utc_time(&curtime);
	    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
	    wtime -= (double) starttime.tv_sec + (double) (starttime.tv_nsec) / 1000000000.0;
	    fprintf(stderr,"%c%c%c%c%"PRIu64" unique (%"PRIu64" duplicate lines) in %.4f seconds\n",8,8,8,8,(uint64_t)Unique_global,(uint64_t)Currem_global,wtime);fflush(stderr);
	    current_utc_time(&starttime);

	    fprintf (stderr,"Occupancy is %"PRIu64"/%"PRIu64" %.04f%%, Maxdepth=%"PRIu64"\n",(uint64_t)Occ_global,HashSize ,(double)(Occ_global)*100.0 / (double)(HashSize),Maxdepth_global);
	   break;

	default:
	    fprintf(stderr,"Unknown ProcMode=%d\n",ProcMode);
	    exit(1);
    }

    Totrem = 0;
    if (Matchtot) {
        fprintf(stderr,"Matching against %"PRIu64" unique lines\n",Matchtot);
    }

    /* Discovery mode (-G): run rule discovery instead of rule file processing */
    if (DiscoverFile) {
	run_discovery(Line, ruleline, ruleline1, workline, outline);
	goto discovery_done;
    }

    for (curfile = 0; curfile < RuleFileCount; curfile++) {
        if (strncmp(RuleFileList[curfile],"stdin",5) == 0)
	    rulefile = stdin;
	else {
	    rulefile = fopen(RuleFileList[curfile],"rb");
	    if (!rulefile) {
	        fprintf(stderr,"Can't open rule file for processing:");
		perror(RuleFileList[curfile]);
		exit(1);
	    }
	}
	fprintf(stderr,"Starting processing rule file: %s\n",RuleFileList[curfile]);

/* process rules */
	while (fgets(ruleline,MAXRULELINE-10,rulefile)) {
	    if (ruleline[0] == '#' || ruleline[0] == ':' || ruleline[0] == '\n' || ruleline[0] == '\r') continue;
	    strncpy(ruleline1,ruleline,MAXRULELINE-10);
	    eol = findeol(ruleline1,MAXRULELINE-10);
	    if (!eol) eol = ruleline1+MAXRULELINE-10;
	    if (*eol == '\n' && eol > ruleline1) *eol-- = 0;
	    if (*eol == '\r' && eol > ruleline1) *eol-- = 0;
	    if (strlen(ruleline1) == 0) continue;

	    if (packrules(ruleline)) {
    badrule:
		fprintf(stderr,"Invalid rule line. Ignored.: %s\n",ruleline);
		continue;
	    }
	    strncpy(workline,"Password",9);
	    if (applyrule(workline, outline, 8, ruleline) == -3)
	       goto badrule;

	    curpos = (Line / Maxt);
	    if (curpos < Maxt) curpos = Line;
	    for (work = 0; work < Line; work += curpos) {
		possess(FreeWaiting);
		wait_for(FreeWaiting, NOT_TO_BE,0);
		job = FreeHead;
		FreeHead = job->next;
		if (FreeHead == NULL) FreeTail = &FreeHead;
		twist(FreeWaiting, BY, -1);
		job->next = NULL; job->func = JOB_MATCH; job->start = work;
		job->plainrule = ruleline1; job->inrule = ruleline;
		if ((work + curpos) > Line )
		    job->end = Line;
		else
		    job->end = work + curpos;
		if (Workthread < Maxt) {
		    launch(procjob,NULL);
		    Workthread++;
		}
		possess(WorkWaiting);
		*WorkTail = job;
		WorkTail = &(job->next);
		twist(WorkWaiting,BY,+1);
	    }
	    possess(FreeWaiting);
	    wait_for(FreeWaiting,TO_BE,Maxt);
	    release(FreeWaiting);
	}
	fclose(rulefile);
	if (Matchtot) {
	    fprintf(stderr,"%"PRIu64" rules matched %"PRIu64" times against %"PRIu64" candidates\n",Rulehits,Matchhits,Matchtot);
	}
    }

discovery_done:
    current_utc_time(&curtime);
    wtime = (double) curtime.tv_sec + (double) (curtime.tv_nsec) / 1000000000.0;
    wtime -= (double) inittime.tv_sec + (double) (inittime.tv_nsec) / 1000000000.0;
    fprintf(stderr,"Total runtime %.4f seconds\n",wtime);

    if (DoDebug || (Matchtot && statfile)) {
	FinalRules = calloc(Rulehits +1, sizeof(struct RuleSort));
	if (!FinalRules) {
	    fprintf(stderr,"No memory for final sort of rules\n");
	    exit(1);
	}
  	ruleline[0] = 0;
	curpos = 0;
	JSLF(PV,MRule,(uint8_t *)ruleline);
	while (PV) {
	    if (curpos > Rulehits) {
	       fprintf(stderr,"Invalid number of final rules found. Bug.\n");
	       exit(1);
	    }
	    FinalRules[curpos].count = *PV;
	    FinalRules[curpos].rule = strdup(ruleline);
	    if (!FinalRules[curpos].rule) {
	        fprintf(stderr,"No memory for final sort\n");
		exit(1);
	    }
	    curpos++;
	    JSLN(PV,MRule,(uint8_t *)ruleline);
	}
	qsort(FinalRules,Rulehits,sizeof(struct RuleSort),rulecomp);
	if (DoDebug) fprintf(stderr,"\n  Count\tRule line\n");
	if (statfile) fprintf(statfile,"#Matching rules for all matched words\n");
	for (curpos = 0; curpos < Rulehits; curpos++) {
	    if (DoDebug) 
	        fprintf(stderr,"%7llu\t%s\n",(long long unsigned int)FinalRules[curpos].count,FinalRules[curpos].rule);
	    if (statfile) fprintf(statfile,"%s\n",FinalRules[curpos].rule);
	}
	if (statfile) fclose(statfile);
    }

    fclose(Fo);
    if (Linefile) fclose(Linefile);
	       

	


    if (Workthread && !DiscoverFile) {
	possess(FreeWaiting);
	wait_for(FreeWaiting, NOT_TO_BE,0);
	job = FreeHead;
	FreeHead = job->next;
	if (FreeHead == NULL) FreeTail = &FreeHead;
	twist(FreeWaiting, BY, -1);
	job->next = NULL;
	job->func = JOB_DONE;
	possess(WorkWaiting);
	*WorkTail = job;
	WorkTail = &(job->next);
	twist(WorkWaiting,BY,+1);
	x = join_all();
    }


    return(0);
}











