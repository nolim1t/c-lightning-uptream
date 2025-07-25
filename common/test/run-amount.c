#include "config.h"
#include "../amount.c"
#include <common/setup.h>
#include <stdio.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_bool */
bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }
/* Generated stub for fromwire_fail */
void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_secp256k1_ecdsa_signature */
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
					secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for fromwire_sha256 */
void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }
/* Generated stub for fromwire_tal_arrn */
u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u64 */
u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for fromwire_u8_array */
void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_secp256k1_ecdsa_signature */
void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

/* Note u32 truncation tests 0 values! */
static void test_amount_sub_fee(struct amount_msat msat,
				u32 base, u32 prop)
{
	struct amount_msat in, in2, out;

	/* If we get msat out, how much do we put in? */
	in = msat;
	assert(amount_msat_add_fee(&in, base, prop));
	/* Fee only increases amount */
	assert(amount_msat_greater_eq(in, msat));

	/* If we put that much in, how much do we get out? */
	out = amount_msat_sub_fee(in, base, prop);
	assert(amount_msat_eq(out, msat));

	/* If we asked for one more out, we'd have to put more in */
	assert(amount_msat_add(&in2, out, AMOUNT_MSAT(1)));
	assert(amount_msat_add_fee(&in2, base, prop));
	assert(amount_msat_greater(in2, in));
}

static void test_amount_fee(struct amount_msat msat, u32 base, u32 prop,
			    struct amount_msat expected_msat)
{
	struct amount_msat fee;
	assert(amount_msat_fee(&fee, msat, base, prop));
	assert(amount_msat_eq(fee, expected_msat));
}

static void test_amount_fee_str(const char *msat_str, u32 base, u32 prop,
				u64 expected)
{
	struct amount_msat msat;
	struct amount_msat expected_msat = amount_msat(expected);
	assert(parse_amount_msat(&msat, msat_str, strlen(msat_str)));
	return test_amount_fee(msat, base, prop, expected_msat);
}

static void test_amount_with_fee(void)
{
	for (int basebits = 0; basebits < 33; basebits++) {
		u32 base = (1ULL << basebits);

		for (int propbits = 0; propbits < 20; propbits++) {
			u32 prop = (1ULL << propbits);

			for (int amtbits1 = 0; amtbits1 < 63; amtbits1++) {
				for (int amtbits2 = 0; amtbits2 < 63; amtbits2++) {
					test_amount_sub_fee(amount_msat((1ULL << amtbits1) | (1ULL << amtbits2)), base, prop);
				}
			}
		}
	}

	for (int basebits = 0; basebits < 33; basebits++) {
		u32 base = (1ULL << basebits);
		for (int propbits = 0; propbits < 20; propbits++) {
			u32 prop = (1ULL << propbits);
			test_amount_fee(amount_msat(0), base, prop,
					amount_msat(base));
		}
	}
	for (int basebits = 0; basebits < 33; basebits++) {
		u32 base = (1ULL << basebits);
		for (int amtbits = 0; amtbits < 63; amtbits++)
			test_amount_fee(amount_msat(1ULL << amtbits), base, 0,
					amount_msat(base));
	}
	for (int amtbits = 0; amtbits < 63; amtbits++)
		test_amount_fee(amount_msat(1ULL << amtbits), 0, 0,
				amount_msat(0));

	test_amount_fee_str("1msat", 1, 1, 1);
	test_amount_fee_str("1msat", 1, 500000, 1);
	test_amount_fee_str("1msat", 1, 1000000, 2);

	test_amount_fee_str("1msat", 1234567890, 1, 1234567890ULL);
	test_amount_fee_str("1msat", 1234567890, 500000, 1234567890ULL);
	test_amount_fee_str("1msat", 1234567890, 1000000, 1234567891ULL);

	test_amount_fee_str("1btc", 1, 1, 100001ULL);
	test_amount_fee_str("1btc", 1, 500000, 50000000001ULL);
	test_amount_fee_str("1btc", 1, 1000000, 100000000001ULL);

	test_amount_fee_str("1btc", 1234567890, 1, 1234667890ULL);
	test_amount_fee_str("1btc", 1234567890, 500000, 51234567890ULL);
	test_amount_fee_str("1btc", 1234567890, 1000000, 101234567890ULL);

	test_amount_fee_str("21000000btc", 1, 1, 2100000000001ULL);
	test_amount_fee_str("21000000btc", 1, 500000, 1050000000000000001ULL);
	test_amount_fee_str("21000000btc", 1, 1000000, 2100000000000000001ULL);

	test_amount_fee_str("21000000btc", 1234567890, 1, 2101234567890ULL);
	test_amount_fee_str("21000000btc", 1234567890, 500000,
			    1050000001234567890ULL);
	test_amount_fee_str("21000000btc", 1234567890, 1000000,
			    2100000001234567890ULL);
}

static void test_case_amount_div(u64 input, u64 div, u64 expected)
{
	struct amount_msat msat = amount_msat(input);
	struct amount_msat expected_msat = amount_msat(expected);
	struct amount_msat result_msat = amount_msat_div(msat, div);
	assert(amount_msat_eq(result_msat, expected_msat));
}

static void test_case_amount_div_ceil(u64 input, u64 div, u64 expected)
{
	struct amount_msat msat = amount_msat(input);
	struct amount_msat expected_msat = amount_msat(expected);
	struct amount_msat result_msat = amount_msat_div_ceil(msat, div);
	assert(amount_msat_eq(result_msat, expected_msat));
}

static void test_amount_div(void)
{
	test_case_amount_div(1, 1, 1);
	test_case_amount_div(1, 2, 0);
	test_case_amount_div(1, 3, 0);

	test_case_amount_div(2, 1, 2);
	test_case_amount_div(2, 2, 1);
	test_case_amount_div(2, 3, 0);

	test_case_amount_div(3, 1, 3);
	test_case_amount_div(3, 2, 1);
	test_case_amount_div(3, 3, 1);
	test_case_amount_div(3, 4, 0);

	test_case_amount_div(10, 1, 10);
	test_case_amount_div(10, 2, 5);
	test_case_amount_div(10, 3, 3);
	test_case_amount_div(10, 4, 2);
	test_case_amount_div(10, 5, 2);
	test_case_amount_div(10, 6, 1);
	test_case_amount_div(10, 7, 1);
	test_case_amount_div(10, 8, 1);
	test_case_amount_div(10, 9, 1);
	test_case_amount_div(10, 10, 1);
	test_case_amount_div(10, 11, 0);

	test_case_amount_div_ceil(1, 1, 1);
	test_case_amount_div_ceil(1, 2, 1);
	test_case_amount_div_ceil(1, 3, 1);

	test_case_amount_div_ceil(2, 1, 2);
	test_case_amount_div_ceil(2, 2, 1);
	test_case_amount_div_ceil(2, 3, 1);

	test_case_amount_div_ceil(3, 1, 3);
	test_case_amount_div_ceil(3, 2, 2);
	test_case_amount_div_ceil(3, 3, 1);
	test_case_amount_div_ceil(3, 4, 1);

	test_case_amount_div_ceil(10, 1, 10);
	test_case_amount_div_ceil(10, 2, 5);
	test_case_amount_div_ceil(10, 3, 4);
	test_case_amount_div_ceil(10, 4, 3);
	test_case_amount_div_ceil(10, 5, 2);
	test_case_amount_div_ceil(10, 6, 2);
	test_case_amount_div_ceil(10, 7, 2);
	test_case_amount_div_ceil(10, 8, 2);
	test_case_amount_div_ceil(10, 9, 2);
	test_case_amount_div_ceil(10, 10, 1);
	test_case_amount_div_ceil(10, 11, 1);
}

#define FAIL_MSAT(msatp, str)					\
	assert(!parse_amount_msat((msatp), (str), strlen(str)))
#define PASS_MSAT(msatp, str, val)					\
	do {								\
		assert(parse_amount_msat((msatp), (str), strlen(str))); \
		assert((msatp)->millisatoshis == val);			\
	} while (0)

#define FAIL_SAT(satp, str) \
	assert(!parse_amount_sat((satp), (str), strlen(str)))
#define PASS_SAT(satp, str, val)					\
	do {								\
		assert(parse_amount_sat((satp), (str), strlen(str)));	\
		assert((satp)->satoshis == val);			\
	} while (0)

int main(int argc, char *argv[])
{
	struct amount_msat msat;
	struct amount_sat sat;

	common_setup(argv[0]);

	/* Grossly malformed */
	FAIL_MSAT(&msat, "x");
	FAIL_MSAT(&msat, "x100");

	PASS_MSAT(&msat, "0", 0);
	PASS_MSAT(&msat, "1", 1);
	PASS_MSAT(&msat, "2100000000000000000", 2100000000000000000ULL);
	FAIL_MSAT(&msat, "0.0");
	FAIL_MSAT(&msat, "0.00000000");
	FAIL_MSAT(&msat, "0.00000000000");
	FAIL_MSAT(&msat, "0.00000000msat");
	FAIL_MSAT(&msat, "-1");

	PASS_MSAT(&msat, "0msat", 0);
	PASS_MSAT(&msat, "1msat", 1);
	PASS_MSAT(&msat, "2100000000000000000msat", 2100000000000000000ULL);
	FAIL_MSAT(&msat, "-1msat");

	PASS_MSAT(&msat, "0sat", 0);
	PASS_MSAT(&msat, "1sat", 1000);
	PASS_MSAT(&msat, "2100000000000000sat", 2100000000000000000ULL);
	FAIL_MSAT(&msat, "-1sat");

	PASS_MSAT(&msat, "0.00000000btc", 0);
	PASS_MSAT(&msat, "0.00000000000btc", 0);
	PASS_MSAT(&msat, "0.00000001btc", 1000);
	PASS_MSAT(&msat, "0.00000000001btc", 1);
	PASS_MSAT(&msat, "1.2btc", 120000000000);
	PASS_MSAT(&msat, "1.23btc", 123000000000);
	PASS_MSAT(&msat, "1.234btc", 123400000000);
	PASS_MSAT(&msat, "1.2345btc", 123450000000);
	PASS_MSAT(&msat, "1.23456btc", 123456000000);
	PASS_MSAT(&msat, "1.234567btc", 123456700000);
	PASS_MSAT(&msat, "1.2345678btc", 123456780000);
	PASS_MSAT(&msat, "1.23456789btc", 123456789000);
	PASS_MSAT(&msat, "1.234567890btc", 123456789000);
	PASS_MSAT(&msat, "1.2345678901btc", 123456789010);
	PASS_MSAT(&msat, "1.23456789012btc", 123456789012);
	FAIL_MSAT(&msat, "1.000000000000btc");
	FAIL_MSAT(&msat, "-1.23456789btc");
	FAIL_MSAT(&msat, "-1.23456789012btc");

	/* Overflowingly big. */
	FAIL_MSAT(&msat, "21000000000000000000000000.00000000btc");

	/* Grossly malformed */
	FAIL_SAT(&sat, "x");
	FAIL_SAT(&sat, "x100");

	PASS_SAT(&sat, "0", 0);
	PASS_SAT(&sat, "1", 1);
	PASS_SAT(&sat, "2100000000000000", 2100000000000000ULL);
	FAIL_SAT(&sat, "0.0");
	FAIL_SAT(&sat, "0.00000000");
	FAIL_SAT(&sat, "0.00000000000");
	FAIL_SAT(&sat, "0.00000000sat");
	FAIL_SAT(&sat, "0.00000000000msat");
	FAIL_SAT(&sat, "-1");

	PASS_SAT(&sat, "0sat", 0);
	PASS_SAT(&sat, "1sat", 1);
	PASS_SAT(&sat, "2100000000000000sat", 2100000000000000ULL);
	FAIL_SAT(&sat, "-1sat");

	PASS_SAT(&sat, "1000msat", 1);
	PASS_SAT(&sat, "1000000msat", 1000);
	PASS_SAT(&sat, "2100000000000000000msat", 2100000000000000ULL);
	PASS_SAT(&sat, "0msat", 0);
	FAIL_SAT(&sat, "100msat");
	FAIL_SAT(&sat, "2000000000000000999msat");
	FAIL_SAT(&sat, "-1000msat");

	PASS_SAT(&sat, "0.00000000btc", 0);
	FAIL_SAT(&sat, "0.00000000000btc");
	PASS_SAT(&sat, "0.00000001btc", 1);
	FAIL_SAT(&sat, "0.00000000001btc");
	PASS_SAT(&sat, "1.23456789btc", 123456789);
	PASS_SAT(&sat, "1.2btc", 120000000);
	PASS_SAT(&sat, "1.23btc", 123000000);
	PASS_SAT(&sat, "1.234btc", 123400000);
	PASS_SAT(&sat, "1.2345btc", 123450000);
	PASS_SAT(&sat, "1.23456btc", 123456000);
	PASS_SAT(&sat, "1.234567btc", 123456700);
	PASS_SAT(&sat, "1.2345678btc", 123456780);
	PASS_SAT(&sat, "1.23456789btc", 123456789);
	FAIL_SAT(&sat, "1.234567890btc");
	FAIL_SAT(&sat, "-1.23456789btc");

	/* Overflowingly big. */
	FAIL_SAT(&sat, "21000000000000000000000000.00000000btc");

	/* Test fmt_amount_msat_btc, fmt_amount_msat */
	for (u64 i = 0; i <= UINT64_MAX / 10; i = i ? i * 10 : 1) {
		const char *with, *without;

		msat.millisatoshis = i;
		with = fmt_amount_msat_btc(tmpctx, msat, true);
		without = fmt_amount_msat_btc(tmpctx, msat, false);
		assert(strends(with, "btc"));
		assert(strlen(with) == strlen(without) + 3);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		msat.millisatoshis++;
		assert(parse_amount_msat(&msat, with, strlen(with)));
		assert(msat.millisatoshis == i);

		with = fmt_amount_msat(tmpctx, msat);
		without = tal_fmt(tmpctx, "%"PRIu64, msat.millisatoshis);
		assert(strends(with, "msat"));
		assert(strlen(with) == strlen(without) + 4);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		msat.millisatoshis++;
		assert(parse_amount_msat(&msat, with, strlen(with)));
		assert(msat.millisatoshis == i);
	}

	/* Test fmt_amount_sat_btc, fmt_amount_sat */
	for (u64 i = 0; i <= UINT64_MAX / 10; i = i ? i * 10 : 1) {
		const char *with, *without;

		sat.satoshis = i;
		with = fmt_amount_sat_btc(tmpctx, sat, true);
		without = fmt_amount_sat_btc(tmpctx, sat, false);
		assert(strends(with, "btc"));
		assert(strlen(with) == strlen(without) + 3);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		sat.satoshis++;
		assert(parse_amount_sat(&sat, with, strlen(with)));
		assert(sat.satoshis == i);

		with = fmt_amount_sat(tmpctx, sat);
		without = tal_fmt(tmpctx, "%"PRIu64, sat.satoshis);
		assert(strends(with, "sat"));
		assert(strlen(with) == strlen(without) + 3);
		assert(strncmp(with, without, strlen(without)) == 0);
		/* Make sure it overwrites. */
		sat.satoshis++;
		assert(parse_amount_sat(&sat, with, strlen(with)));
		assert(sat.satoshis == i);
	}

	test_amount_with_fee();
	test_amount_div();
	common_shutdown();
}
