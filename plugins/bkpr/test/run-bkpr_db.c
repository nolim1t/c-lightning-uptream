#include "config.h"

#include <ccan/tal/str/str.h>
#include <db/common.h>

#include "common/json_filter.c"
#include "plugins/bkpr/db.c"
#include "plugins/libplugin.c"

#include "test_utils.h"

#include <common/fee_states.h>
#include <common/htlc.h>
#include <common/json_stream.h>
#include <common/setup.h>
#include <common/utils.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/channel_event.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/wire.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for account_entry_tag_str */
const char *account_entry_tag_str(enum account_entry_tag tag UNNEEDED)
{ fprintf(stderr, "account_entry_tag_str called!\n"); abort(); }
/* Generated stub for command_fail_badparam */
struct command_result *command_fail_badparam(struct command *cmd UNNEEDED,
					     const char *paramname UNNEEDED,
					     const char *buffer UNNEEDED,
					     const jsmntok_t *tok UNNEEDED,
					     const char *msg UNNEEDED)
{ fprintf(stderr, "command_fail_badparam called!\n"); abort(); }
/* Generated stub for daemon_developer_mode */
bool daemon_developer_mode(char *argv[])
{ fprintf(stderr, "daemon_developer_mode called!\n"); abort(); }
/* Generated stub for daemon_setup */
void daemon_setup(const char *argv0 UNNEEDED,
		  void (*backtrace_print)(const char *fmt UNNEEDED, ...) UNNEEDED,
		  void (*backtrace_exit)(void))
{ fprintf(stderr, "daemon_setup called!\n"); abort(); }
/* Generated stub for deprecated_ok_ */
bool  deprecated_ok_(bool deprecated_apis UNNEEDED,
		    const char *feature UNNEEDED,
		    const char *start UNNEEDED,
		    const char *end UNNEEDED,
		    const char **begs UNNEEDED,
		    void (*complain)(const char *feat UNNEEDED, bool allowing UNNEEDED, void *) UNNEEDED,
		    void *cbarg UNNEEDED)
{ fprintf(stderr, "deprecated_ok_ called!\n"); abort(); }
/* Generated stub for first_fee_state */
enum htlc_state first_fee_state(enum side opener UNNEEDED)
{ fprintf(stderr, "first_fee_state called!\n"); abort(); }
/* Generated stub for fmt_channel_id */
char *fmt_channel_id(const tal_t *ctx UNNEEDED, const struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "fmt_channel_id called!\n"); abort(); }
/* Generated stub for fmt_wireaddr_without_port */
char *fmt_wireaddr_without_port(const tal_t *ctx UNNEEDED, const struct wireaddr *a UNNEEDED)
{ fprintf(stderr, "fmt_wireaddr_without_port called!\n"); abort(); }
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
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
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
/* Generated stub for fromwire_wireaddr */
bool fromwire_wireaddr(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct wireaddr *addr UNNEEDED)
{ fprintf(stderr, "fromwire_wireaddr called!\n"); abort(); }
/* Generated stub for fromwire_wirestring */
char *fromwire_wirestring(const tal_t *ctx UNNEEDED, const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_wirestring called!\n"); abort(); }
/* Generated stub for htlc_state_flags */
int htlc_state_flags(enum htlc_state state UNNEEDED)
{ fprintf(stderr, "htlc_state_flags called!\n"); abort(); }
/* Generated stub for htlc_state_name */
const char *htlc_state_name(enum htlc_state s UNNEEDED)
{ fprintf(stderr, "htlc_state_name called!\n"); abort(); }
/* Generated stub for is_asterix_notification */
bool is_asterix_notification(const char *notification_name UNNEEDED,
			     const char *subscriptions UNNEEDED)
{ fprintf(stderr, "is_asterix_notification called!\n"); abort(); }
/* Generated stub for json_get_id */
const char *json_get_id(const tal_t *ctx UNNEEDED,
			const char *buffer UNNEEDED, const jsmntok_t *obj UNNEEDED)
{ fprintf(stderr, "json_get_id called!\n"); abort(); }
/* Generated stub for json_get_member */
const jsmntok_t *json_get_member(const char *buffer UNNEEDED, const jsmntok_t tok[] UNNEEDED,
				 const char *label UNNEEDED)
{ fprintf(stderr, "json_get_member called!\n"); abort(); }
/* Generated stub for json_next */
const jsmntok_t *json_next(const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_next called!\n"); abort(); }
/* Generated stub for json_parse_input */
bool json_parse_input(jsmn_parser *parser UNNEEDED,
		      jsmntok_t **toks UNNEEDED,
		      const char *input UNNEEDED, int len UNNEEDED,
		      bool *complete UNNEEDED)
{ fprintf(stderr, "json_parse_input called!\n"); abort(); }
/* Generated stub for json_parse_simple */
jsmntok_t *json_parse_simple(const tal_t *ctx UNNEEDED, const char *input UNNEEDED, int len UNNEEDED)
{ fprintf(stderr, "json_parse_simple called!\n"); abort(); }
/* Generated stub for json_scan */
const char *json_scan(const tal_t *ctx UNNEEDED,
		      const char *buffer UNNEEDED,
		      const jsmntok_t *tok UNNEEDED,
		      const char *guide UNNEEDED,
		      ...)
{ fprintf(stderr, "json_scan called!\n"); abort(); }
/* Generated stub for json_scanv */
const char *json_scanv(const tal_t *ctx UNNEEDED,
		       const char *buffer UNNEEDED,
		       const jsmntok_t *tok UNNEEDED,
		       const char *guide UNNEEDED,
		       va_list ap UNNEEDED)
{ fprintf(stderr, "json_scanv called!\n"); abort(); }
/* Generated stub for json_strdup */
char *json_strdup(const tal_t *ctx UNNEEDED, const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_strdup called!\n"); abort(); }
/* Generated stub for json_to_bool */
bool json_to_bool(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, bool *b UNNEEDED)
{ fprintf(stderr, "json_to_bool called!\n"); abort(); }
/* Generated stub for json_to_int */
bool json_to_int(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, int *num UNNEEDED)
{ fprintf(stderr, "json_to_int called!\n"); abort(); }
/* Generated stub for json_to_msat */
bool json_to_msat(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		  struct amount_msat *msat UNNEEDED)
{ fprintf(stderr, "json_to_msat called!\n"); abort(); }
/* Generated stub for json_to_node_id */
bool json_to_node_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			       struct node_id *id UNNEEDED)
{ fprintf(stderr, "json_to_node_id called!\n"); abort(); }
/* Generated stub for json_to_number */
bool json_to_number(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		    unsigned int *num UNNEEDED)
{ fprintf(stderr, "json_to_number called!\n"); abort(); }
/* Generated stub for json_to_secret */
bool json_to_secret(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, struct secret *dest UNNEEDED)
{ fprintf(stderr, "json_to_secret called!\n"); abort(); }
/* Generated stub for json_to_short_channel_id */
bool json_to_short_channel_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			      struct short_channel_id *scid UNNEEDED)
{ fprintf(stderr, "json_to_short_channel_id called!\n"); abort(); }
/* Generated stub for json_to_txid */
bool json_to_txid(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		  struct bitcoin_txid *txid UNNEEDED)
{ fprintf(stderr, "json_to_txid called!\n"); abort(); }
/* Generated stub for json_to_u16 */
bool json_to_u16(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
                 uint16_t *num UNNEEDED)
{ fprintf(stderr, "json_to_u16 called!\n"); abort(); }
/* Generated stub for json_tok_bin_from_hex */
u8 *json_tok_bin_from_hex(const tal_t *ctx UNNEEDED, const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_tok_bin_from_hex called!\n"); abort(); }
/* Generated stub for json_tok_copy */
jsmntok_t *json_tok_copy(const tal_t *ctx UNNEEDED, const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_tok_copy called!\n"); abort(); }
/* Generated stub for json_tok_full */
const char *json_tok_full(const char *buffer UNNEEDED, const jsmntok_t *t UNNEEDED)
{ fprintf(stderr, "json_tok_full called!\n"); abort(); }
/* Generated stub for json_tok_full_len */
int json_tok_full_len(const jsmntok_t *t UNNEEDED)
{ fprintf(stderr, "json_tok_full_len called!\n"); abort(); }
/* Generated stub for json_tok_remove */
void json_tok_remove(jsmntok_t **tokens UNNEEDED,
		     jsmntok_t *obj_or_array UNNEEDED, const jsmntok_t *tok UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "json_tok_remove called!\n"); abort(); }
/* Generated stub for json_tok_streq */
bool json_tok_streq(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, const char *str UNNEEDED)
{ fprintf(stderr, "json_tok_streq called!\n"); abort(); }
/* Generated stub for last_fee_state */
enum htlc_state last_fee_state(enum side opener UNNEEDED)
{ fprintf(stderr, "last_fee_state called!\n"); abort(); }
/* Generated stub for log_level_name */
const char *log_level_name(enum log_level level UNNEEDED)
{ fprintf(stderr, "log_level_name called!\n"); abort(); }
/* Generated stub for new_channel_event */
struct channel_event *new_channel_event(const tal_t *ctx UNNEEDED,
					const char *tag UNNEEDED,
					struct amount_msat credit UNNEEDED,
					struct amount_msat debit UNNEEDED,
					struct amount_msat fees UNNEEDED,
					const char *currency UNNEEDED,
					struct sha256 *payment_id STEALS UNNEEDED,
					u32 part_id UNNEEDED,
					u64 timestamp UNNEEDED)
{ fprintf(stderr, "new_channel_event called!\n"); abort(); }
/* Generated stub for param_check */
bool param_check(struct command *cmd UNNEEDED,
		 const char *buffer UNNEEDED,
		 const jsmntok_t tokens[] UNNEEDED, ...)
{ fprintf(stderr, "param_check called!\n"); abort(); }
/* Generated stub for toks_alloc */
jsmntok_t *toks_alloc(const tal_t *ctx UNNEEDED)
{ fprintf(stderr, "toks_alloc called!\n"); abort(); }
/* Generated stub for toks_reset */
void toks_reset(jsmntok_t *toks UNNEEDED)
{ fprintf(stderr, "toks_reset called!\n"); abort(); }
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
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
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
/* Generated stub for towire_wirestring */
void towire_wirestring(u8 **pptr UNNEEDED, const char *str UNNEEDED)
{ fprintf(stderr, "towire_wirestring called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

static char *tmp_dsn(const tal_t *ctx)
{
	char *dsn, *filename;
	int fd = tmpdir_mkstemp(ctx, "lacct-db-XXXXXX", &filename);
	if (fd == -1)
		return NULL;
	close(fd);

	dsn = tal_fmt(NULL, "sqlite3://%s", filename);
	tal_free(filename);

	return dsn;
}

static struct db *create_test_db(void)
{
	struct db *db;
	char *dsn;

	dsn = tmp_dsn(NULL);
	db = db_open(NULL, dsn, true, db_error, (struct plugin *)NULL);
	db->data_version = 0;
	db->report_changes_fn = NULL;

	tal_free(dsn);
	return db;
}

static bool test_db_migrate(struct plugin *plugin)
{
	struct db *db = create_test_db();

	CHECK(db);
	db_begin_transaction(db);
	CHECK(db_get_version(db) == -1);
	CHECK(db_migrate(plugin, db) == true);
	db_commit_transaction(db);

	db_begin_transaction(db);
	CHECK(db_get_version(db) == ARRAY_SIZE(db_migrations) - 1);
	db_commit_transaction(db);

	db_begin_transaction(db);
	CHECK(db_migrate(plugin, db) == false);
	db_commit_transaction(db);

	tal_free(db);
	return true;
}

int main(int argc, char *argv[])
{
	bool ok = true;
	/* Dummy for migration hooks */
	struct plugin *plugin = tal(NULL, struct plugin);
	list_head_init(&plugin->js_list);

	common_setup(argv[0]);

	if (HAVE_SQLITE3) {
		ok &= test_db_migrate(plugin);
	}

	tal_free(plugin);
	common_shutdown();
	trace_cleanup();
	return !ok;
}
