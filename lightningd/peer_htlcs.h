/* All about the HTLCs/commitment transactions for a particular peer. */
#ifndef LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#define LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#include "config.h"
#include <common/htlc_wire.h>

struct channel;
struct htlc_in;
struct htlc_in_map;
struct htlc_out;
struct htlc_out_map;
struct htlc_stub;
struct lightningd;
struct json_stream;

/* Get all HTLCs for a peer, to send in init message. */
const struct existing_htlc **peer_htlcs(const tal_t *ctx,
					const struct channel *channel);

void free_htlcs(struct lightningd *ld, const struct channel *channel);

void peer_sending_commitsig(struct channel *channel, const u8 *msg);
void peer_got_commitsig(struct channel *channel, const u8 *msg);
void peer_got_revoke(struct channel *channel, const u8 *msg);

void update_per_commit_point(struct channel *channel,
			     const struct pubkey *per_commitment_point);

/* Returns NULL on success, otherwise failmsg*/
const u8 *send_htlc_out(const tal_t *ctx,
			struct channel *out,
			struct amount_msat amount, u32 cltv,
			struct amount_msat final_msat,
			const struct sha256 *payment_hash,
			const struct pubkey *path_key,
			u64 partid,
			u64 groupid,
			const u8 *onion_routing_packet,
			struct htlc_in *in,
			struct htlc_out **houtp);

void onchain_failed_our_htlc(const struct channel *channel,
			     const struct htlc_stub *htlc,
			     const char *why,
			     bool should_exist);
void onchain_fulfilled_htlc(struct channel *channel,
			    const struct preimage *preimage);

void htlcs_notify_new_block(struct lightningd *ld);

/* Only defined if COMPAT_V061 */
void fixup_htlcs_out(struct lightningd *ld);

void htlcs_resubmit(struct lightningd *ld,
		    struct htlc_in_map *unconnected_htlcs_in STEALS);

/* Apply tweak to ephemeral key if path_key is non-NULL, then do ECDH */
bool ecdh_maybe_blinding(const struct pubkey *ephemeral_key,
			 const struct pubkey *path_key,
			 struct secret *ss);

/* Select best (highest capacity) to peer.  If hint is set, must match that
 * feerate */
struct channel *best_channel(struct lightningd *ld,
			     const struct peer *next_peer,
			     struct amount_msat amt_to_forward,
			     const struct channel *hint);

/* For HTLCs which terminate here, invoice payment calls one of these. */
void fulfill_htlc(struct htlc_in *hin, const struct preimage *preimage);
void local_fail_in_htlc(struct htlc_in *hin, const u8 *failmsg TAKES);
void local_fail_in_htlc_needs_update(struct htlc_in *hin,
				     const u8 *failmsg_needs_update TAKES,
				     const struct short_channel_id *failmsg_scid);

/* Helper to create (common) WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS */
const u8 *failmsg_incorrect_or_unknown(const tal_t *ctx,
				       struct lightningd *ld,
				       struct amount_msat msat);

/* For wallet.c to tell us when indexes changed */
void htlcs_index_deleted(struct lightningd *ld,
			 const struct channel *channel,
			 u64 num_deleted);

u64 htlcs_index_created(struct lightningd *ld,
			u64 htlc_id,
			const struct channel *channel,
			const struct sha256 *payment_hash,
			enum side owner,
			u32 expiry,
			struct amount_msat amount,
			enum htlc_state hstate);

u64 htlcs_index_update_status(struct lightningd *ld,
			      u64 htlc_id,
			      const struct channel *channel,
			      const struct sha256 *payment_hash,
			      enum side owner,
			      u32 expiry,
			      struct amount_msat amount,
			      enum htlc_state hstate);

#endif /* LIGHTNING_LIGHTNINGD_PEER_HTLCS_H */
