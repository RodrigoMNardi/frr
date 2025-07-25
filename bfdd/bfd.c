// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * bfd.c: implements the BFD protocol.
 *
 * Authors
 * -------
 * Shrijeet Mukherjee [shm@cumulusnetworks.com]
 * Kanna Rajagopal [kanna@cumulusnetworks.com]
 * Radhika Mahankali [Radhika@cumulusnetworks.com]
 */

#include <zebra.h>

#include "lib/jhash.h"
#include "lib/network.h"

#include "bfd.h"

DEFINE_MTYPE_STATIC(BFDD, BFDD_CONFIG, "long-lived configuration memory");
DEFINE_MTYPE_STATIC(BFDD, BFDD_PROFILE, "long-lived profile memory");
DEFINE_MTYPE_STATIC(BFDD, BFDD_SESSION_OBSERVER, "Session observer");
DEFINE_MTYPE_STATIC(BFDD, BFDD_VRF, "BFD VRF");
DEFINE_MTYPE_STATIC(BFDD, SBFD_REFLECTOR, "SBFD REFLECTOR");
DEFINE_MTYPE_STATIC(BFDD, BFD_PERM_VRF, "BFD perm vrf data");

/*
 * Prototypes
 */
static uint32_t ptm_bfd_gen_ID(void);
static void ptm_bfd_echo_xmt_TO(struct bfd_session *bfd);
static struct bfd_session *bfd_find_disc(struct sockaddr_any *sa,
					 uint32_t ldisc);
static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc);
static const char *get_diag_str(int diag);

static void bs_admin_down_handler(struct bfd_session *bs, int nstate);
static void bs_down_handler(struct bfd_session *bs, int nstate);
static void bs_init_handler(struct bfd_session *bs, int nstate);
static void bs_up_handler(struct bfd_session *bs, int nstate);

static void ptm_sbfd_echo_xmt_TO(struct bfd_session *bfd);
static void sbfd_down_handler(struct bfd_session *bs, int nstate);
static void sbfd_up_handler(struct bfd_session *bs, int nstate);

/**
 * Remove BFD profile from all BFD sessions so we don't leave dangling
 * pointers.
 */
static void bfd_profile_detach(struct bfd_profile *bp);

/* Zeroed array with the size of an IPv6 address. */
struct in6_addr zero_addr;

/** BFD profiles list. */
struct bfdproflist bplist;

/*
 * Data structures and functions for managing
 * permitted VRFs for BFD sessions.
 */
static unsigned int bfd_perm_vrfs_hash_do(const struct bfd_perm_vrf *vrf);
static bool bfd_perm_vrfs_hash_cmp(const struct bfd_perm_vrf *vrf1,
				   const struct bfd_perm_vrf *vrf2);
static void destroy_bfd_perm_vrfs_data(void);

DECLARE_HASH(bfd_perm_vrfs, struct bfd_perm_vrf, itm, bfd_perm_vrfs_hash_cmp,
	     bfd_perm_vrfs_hash_do);
struct bfd_perm_vrfs_head bfd_perm_vrfs;

/*
 * Functions
 */
struct bfd_profile *bfd_profile_lookup(const char *name)
{
	struct bfd_profile *bp;

	TAILQ_FOREACH (bp, &bplist, entry) {
		if (strcmp(name, bp->name))
			continue;

		return bp;
	}

	return NULL;
}

static void bfd_profile_set_default(struct bfd_profile *bp)
{
	bp->admin_shutdown = false;
	bp->detection_multiplier = BFD_DEFDETECTMULT;
	bp->echo_mode = false;
	bp->passive = false;
	bp->log_session_changes = false;
	bp->minimum_ttl = BFD_DEF_MHOP_TTL;
	bp->min_echo_rx = BFD_DEF_REQ_MIN_ECHO_RX;
	bp->min_echo_tx = BFD_DEF_DES_MIN_ECHO_TX;
	bp->min_rx = BFD_DEFREQUIREDMINRX;
	bp->min_tx = BFD_DEFDESIREDMINTX;
}

struct bfd_profile *bfd_profile_new(const char *name)
{
	struct bfd_profile *bp;

	/* Search for duplicates. */
	if (bfd_profile_lookup(name) != NULL)
		return NULL;

	/* Allocate, name it and put into list. */
	bp = XCALLOC(MTYPE_BFDD_PROFILE, sizeof(*bp));
	strlcpy(bp->name, name, sizeof(bp->name));
	TAILQ_INSERT_TAIL(&bplist, bp, entry);

	/* Set default values. */
	bfd_profile_set_default(bp);

	return bp;
}

void bfd_profile_free(struct bfd_profile *bp)
{
	/* Detach from any session. */
	if (bglobal.bg_shutdown == false)
		bfd_profile_detach(bp);

	/* Remove from global list. */
	TAILQ_REMOVE(&bplist, bp, entry);

	XFREE(MTYPE_BFDD_PROFILE, bp);
}

void bfd_profile_apply(const char *profname, struct bfd_session *bs)
{
	struct bfd_profile *bp;

	/* Remove previous profile if any. */
	if (bs->profile_name) {
		/* We are changing profiles. */
		if (strcmp(bs->profile_name, profname)) {
			XFREE(MTYPE_BFDD_PROFILE, bs->profile_name);
			bs->profile_name =
				XSTRDUP(MTYPE_BFDD_PROFILE, profname);
		}
	} else /* Save the current profile name (in case it doesn't exist). */
		bs->profile_name = XSTRDUP(MTYPE_BFDD_PROFILE, profname);

	/* Look up new profile to apply. */
	bp = bfd_profile_lookup(profname);

	/* Point to profile if it exists. */
	bs->profile = bp;

	/* Apply configuration. */
	bfd_session_apply(bs);
}

void bfd_session_apply(struct bfd_session *bs)
{
	struct bfd_profile *bp;
	uint32_t min_tx = bs->timers.desired_min_tx;
	uint32_t min_rx = bs->timers.required_min_rx;

	/* Pick the source of configuration. */
	bp = bs->profile ? bs->profile : &bs->peer_profile;

	/* Set multiplier if not the default. */
	if (bs->peer_profile.detection_multiplier == BFD_DEFDETECTMULT)
		bs->detect_mult = bp->detection_multiplier;
	else
		bs->detect_mult = bs->peer_profile.detection_multiplier;

	/* Set timers if not the default. */
	if (bs->peer_profile.min_tx == BFD_DEFDESIREDMINTX)
		bs->timers.desired_min_tx = bp->min_tx;
	else
		bs->timers.desired_min_tx = bs->peer_profile.min_tx;

	if (bs->peer_profile.min_rx == BFD_DEFREQUIREDMINRX)
		bs->timers.required_min_rx = bp->min_rx;
	else
		bs->timers.required_min_rx = bs->peer_profile.min_rx;

	/* We can only apply echo options on single hop sessions. */
	if (!CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		/* Configure echo timers if they were default. */
		if (bs->peer_profile.min_echo_rx == BFD_DEF_REQ_MIN_ECHO_RX)
			bs->timers.required_min_echo_rx = bp->min_echo_rx;
		else
			bs->timers.required_min_echo_rx =
				bs->peer_profile.min_echo_rx;

		if (bs->peer_profile.min_echo_tx == BFD_DEF_DES_MIN_ECHO_TX)
			bs->timers.desired_min_echo_tx = bp->min_echo_tx;
		else
			bs->timers.desired_min_echo_tx =
				bs->peer_profile.min_echo_tx;

		/* Toggle echo if default value. */
		if (bs->peer_profile.echo_mode == false)
			bfd_set_echo(bs, bp->echo_mode);
		else
			bfd_set_echo(bs, bs->peer_profile.echo_mode);
	} else {
		/* Configure the TTL packet filter. */
		if (bs->peer_profile.minimum_ttl == BFD_DEF_MHOP_TTL)
			bs->mh_ttl = bp->minimum_ttl;
		else
			bs->mh_ttl = bs->peer_profile.minimum_ttl;
	}

	/* Toggle 'passive-mode' if default value. */
	if (bs->bfd_mode == BFD_MODE_TYPE_BFD) {
		if (bs->peer_profile.passive == false)
			bfd_set_passive_mode(bs, bp->passive);
		else
			bfd_set_passive_mode(bs, bs->peer_profile.passive);
	}

	/* Toggle 'no shutdown' if default value. */
	if (bs->peer_profile.admin_shutdown == false)
		bfd_set_shutdown(bs, bp->admin_shutdown);
	else
		bfd_set_shutdown(bs, bs->peer_profile.admin_shutdown);

	/* Toggle 'no log-session-changes' if default value. */
	if (bs->peer_profile.log_session_changes == false)
		bfd_set_log_session_changes(bs, bp->log_session_changes);
	else
		bfd_set_log_session_changes(bs, bs->peer_profile.log_session_changes);

	/* If session interval changed negotiate new timers. */
	if (bs->ses_state == PTM_BFD_UP
	    && (bs->timers.desired_min_tx != min_tx
		|| bs->timers.required_min_rx != min_rx))
		bfd_set_polling(bs);

	/* Send updated information to data plane. */
	bfd_dplane_update_session(bs);
}

void bfd_profile_remove(struct bfd_session *bs)
{
	/* Remove any previous set profile name. */
	XFREE(MTYPE_BFDD_PROFILE, bs->profile_name);
	bs->profile = NULL;

	bfd_session_apply(bs);
}

void gen_bfd_key(struct bfd_key *key, struct sockaddr_any *peer, struct sockaddr_any *local,
		 bool mhop, const char *ifname, const char *vrfname, const char *bfdname)
{
	struct vrf *vrf = NULL;

	memset(key, 0, sizeof(*key));

	switch (peer->sa_sin.sin_family) {
	case AF_INET:
		key->family = AF_INET;
		memcpy(&key->peer, &peer->sa_sin.sin_addr,
		       sizeof(peer->sa_sin.sin_addr));
		memcpy(&key->local, &local->sa_sin.sin_addr,
		       sizeof(local->sa_sin.sin_addr));
		break;
	case AF_INET6:
		key->family = AF_INET6;
		memcpy(&key->peer, &peer->sa_sin6.sin6_addr,
		       sizeof(peer->sa_sin6.sin6_addr));
		memcpy(&key->local, &local->sa_sin6.sin6_addr,
		       sizeof(local->sa_sin6.sin6_addr));
		break;
	}

	key->mhop = mhop;
	if (ifname && ifname[0])
		strlcpy(key->ifname, ifname, sizeof(key->ifname));
	if (vrfname && vrfname[0] && strcmp(vrfname, VRF_DEFAULT_NAME) != 0) {
		vrf = vrf_lookup_by_name(vrfname);
		if (vrf) {
			strlcpy(key->vrfname, vrf->name, sizeof(key->vrfname));
		} else {
			strlcpy(key->vrfname, vrfname, sizeof(key->vrfname));
		}
	} else {
		strlcpy(key->vrfname, VRF_DEFAULT_NAME, sizeof(key->vrfname));
	}

	if (bfdname && bfdname[0]) {
		strlcpy(key->bfdname, bfdname, sizeof(key->bfdname));
	}
}

struct bfd_session *bs_peer_find(struct bfd_peer_cfg *bpc)
{
	struct bfd_key key;

	/* Otherwise fallback to peer/local hash lookup. */
	gen_bfd_key(&key, &bpc->bpc_peer, &bpc->bpc_local, bpc->bpc_mhop, bpc->bpc_localif,
		    bpc->bpc_vrfname, bpc->bfd_name);

	return bfd_key_lookup(&key);
}

/*
 * Starts a disabled BFD session.
 *
 * A session is disabled when the specified interface/VRF doesn't exist
 * yet. It might happen on FRR boot or with virtual interfaces.
 */
int bfd_session_enable(struct bfd_session *bs)
{
	struct interface *ifp = NULL;
	struct vrf *vrf = NULL;
	int psock;

	/* We are using data plane, we don't need software. */
	if (bs->bdc)
		return 0;

	/*
	 * If the interface or VRF doesn't exist, then we must register
	 * the session but delay its start.
	 */
	if (bs->key.vrfname[0]) {
		vrf = vrf_lookup_by_name(bs->key.vrfname);
		if (vrf == NULL) {
			zlog_err(
				"session-enable: specified VRF %s doesn't exists.",
				bs->key.vrfname);
			return 0;
		}
	} else {
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	}

	assert(vrf);

	if (bs->key.ifname[0]) {
		ifp = if_lookup_by_name(bs->key.ifname, vrf->vrf_id);
		if (ifp == NULL) {
			zlog_err(
				"session-enable: specified interface %s (VRF %s) doesn't exist.",
				bs->key.ifname, vrf->name);
			return 0;
		}
	}

	/* Assign interface/VRF pointers. */
	bs->vrf = vrf;

	/* Assign interface pointer (if any). */
	bs->ifp = ifp;

	/* Attempt to use data plane. */
	if (bglobal.bg_use_dplane && bfd_dplane_add_session(bs) == 0)
		return 0;

	/* Sanity check: don't leak open sockets. */
	if (bs->sock != -1) {
		if (bglobal.debug_peer_event)
			zlog_debug("%s: previous socket open", __func__);

		close(bs->sock);
		bs->sock = -1;
	}

	/*
	 * Get socket for transmitting control packets.  Note that if we
	 * could use the destination port (3784) for the source
	 * port we wouldn't need a socket per session.
	 */
	if (bs->bfd_mode == BFD_MODE_TYPE_SBFD_ECHO || bs->bfd_mode == BFD_MODE_TYPE_SBFD_INIT) {
		psock = bp_peer_srh_socketv6(bs);
		if (psock < 0) {
			zlog_err("bp_peer_srh_socketv6 error");
			return 0;
		}
	} else if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6) == 0) {
		psock = bp_peer_socket(bs);
		if (psock == -1) {
			zlog_err("bp_peer_socket error");
			return 0;
		}
	} else {
		psock = bp_peer_socketv6(bs);
		if (psock == -1) {
			zlog_err("bp_peer_socketv6 error");
			return 0;
		}
	}

	/*
	 * We've got a valid socket, lets start the timers and the
	 * protocol.
	 */
	bs->sock = psock;

	/* Only start timers if we are using active mode. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE) == 0) {
		if (bs->bfd_mode == BFD_MODE_TYPE_SBFD_ECHO) {
			/*enable receive echo response*/
			bfd_set_echo(bs, true);

			bs->echo_detect_TO = (bs->remote_detect_mult * bs->echo_xmt_TO);
			sbfd_echo_recvtimer_update(bs);
			ptm_bfd_start_xmt_timer(bs, true);
		} else {
			bfd_recvtimer_update(bs);
			ptm_bfd_start_xmt_timer(bs, false);
		}
	}
	/* initialize RTT */
	bfd_rtt_init(bs);

	return 0;
}

/*
 * Disabled a running BFD session.
 *
 * A session is disabled when the specified interface/VRF gets removed
 * (e.g. virtual interfaces).
 */
void bfd_session_disable(struct bfd_session *bs)
{
	/* We are using data plane, we don't need software. */
	if (bs->bdc)
		return;

	/* Free up socket resources. */
	if (bs->sock != -1) {
		close(bs->sock);
		bs->sock = -1;
	}

	/* Disable all timers. */
	bfd_recvtimer_delete(bs);
	bfd_xmttimer_delete(bs);
	ptm_bfd_echo_stop(bs);
	bs->vrf = NULL;
	bs->ifp = NULL;

	/* Set session down so it doesn't report UP and disabled. */
	ptm_bfd_sess_dn(bs, BD_PATH_DOWN);
}

static uint32_t ptm_bfd_gen_ID(void)
{
	uint32_t session_id;

	/*
	 * RFC 5880, Section 6.8.1. recommends that we should generate
	 * random session identification numbers.
	 */
	do {
		session_id = CHECK_FLAG((frr_weak_random() << 16), 0xFFFF0000) |
			     CHECK_FLAG(frr_weak_random(), 0x0000FFFF);
	} while (session_id == 0 || bfd_id_lookup(session_id) != NULL);

	return session_id;
}

void ptm_bfd_start_xmt_timer(struct bfd_session *bfd, bool is_echo)
{
	uint64_t jitter, xmt_TO;
	int maxpercent;

	xmt_TO = is_echo ? bfd->echo_xmt_TO : bfd->xmt_TO;

	/*
	 * From section 6.5.2: trasmit interval should be randomly jittered
	 * between
	 * 75% and 100% of nominal value, unless detect_mult is 1, then should
	 * be
	 * between 75% and 90%.
	 */
	maxpercent = (bfd->detect_mult == 1) ? 16 : 26;
	jitter = (xmt_TO * (75 + (frr_weak_random() % maxpercent))) / 100;
	/* XXX remove that division above */

	if (bfd->bfd_mode == BFD_MODE_TYPE_SBFD_ECHO || bfd->bfd_mode == BFD_MODE_TYPE_SBFD_INIT) {
		if (is_echo)
			sbfd_echo_xmttimer_update(bfd, jitter);
		else
			sbfd_init_xmttimer_update(bfd, jitter);

	} else {
		if (is_echo)
			bfd_echo_xmttimer_update(bfd, jitter);
		else
			bfd_xmttimer_update(bfd, jitter);
	}
}

static void ptm_bfd_echo_xmt_TO(struct bfd_session *bfd)
{
	/* Send the scheduled echo  packet */
	/* if ipv4 use the new echo implementation that causes
	 * the packet to be looped in forwarding plane of peer
	 */
	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6) == 0)
#ifdef BFD_LINUX
		ptm_bfd_echo_fp_snd(bfd);
#else
		ptm_bfd_echo_snd(bfd);
#endif
	else
		ptm_bfd_echo_snd(bfd);

	/* Restart the timer for next time */
	ptm_bfd_start_xmt_timer(bfd, true);
}

void ptm_bfd_xmt_TO(struct bfd_session *bfd, int fbit)
{
	/* Send the scheduled control packet */
	ptm_bfd_snd(bfd, fbit);

	/* Restart the timer for next time */
	ptm_bfd_start_xmt_timer(bfd, false);
}

static void ptm_sbfd_echo_xmt_TO(struct bfd_session *bfd)
{
	/* Send the scheduled sbfd-echo  packet */
	ptm_sbfd_echo_snd(bfd);

	/* Restart the timer for next time */
	ptm_bfd_start_xmt_timer(bfd, true);
}

void ptm_sbfd_init_xmt_TO(struct bfd_session *bfd, int fbit)
{
	/* Send the scheduled control packet */
	ptm_sbfd_initiator_snd(bfd, fbit);

	/* Restart the timer for next time */
	ptm_bfd_start_xmt_timer(bfd, false);
}

void ptm_sbfd_init_reset(struct bfd_session *bfd)
{
	bfd->xmt_TO = BFD_DEF_SLOWTX;
	bfd->detect_TO = 0;
	ptm_sbfd_init_xmt_TO(bfd, 0);
}
void ptm_sbfd_echo_reset(struct bfd_session *bfd)
{
	bfd->echo_xmt_TO = SBFD_ECHO_DEF_SLOWTX;
	bfd->echo_detect_TO = 0;
	ptm_sbfd_echo_xmt_TO(bfd);
}

void ptm_bfd_echo_stop(struct bfd_session *bfd)
{
	bfd->echo_xmt_TO = 0;
	bfd->echo_detect_TO = 0;
	UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);

	bfd_echo_xmttimer_delete(bfd);
	bfd_echo_recvtimer_delete(bfd);
}

void ptm_bfd_echo_start(struct bfd_session *bfd)
{
	bfd->echo_detect_TO = (bfd->remote_detect_mult * bfd->echo_xmt_TO);
	if (bfd->echo_detect_TO > 0) {
		bfd_echo_recvtimer_update(bfd);
		ptm_bfd_echo_xmt_TO(bfd);
	}
}

void ptm_bfd_sess_up(struct bfd_session *bfd)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = 0;
	bfd->ses_state = PTM_BFD_UP;
	monotime(&bfd->uptime);

	/* Connection is up, lets negotiate timers. */
	bfd_set_polling(bfd);

	/* Start sending control packets with poll bit immediately. */
	ptm_bfd_snd(bfd, 0);

	ptm_bfd_notify(bfd, bfd->ses_state);

	if (old_state != bfd->ses_state) {
		bfd->stats.session_up++;
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: [%s] %s -> %s",
				   bs_to_string(bfd), state_list[old_state].str,
				   state_list[bfd->ses_state].str);
		if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES))
			zlog_notice("Session-Change: [%s] %s -> %s", bs_to_string(bfd),
				    state_list[old_state].str, state_list[bfd->ses_state].str);
	}
}

void ptm_bfd_sess_dn(struct bfd_session *bfd, uint8_t diag)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = diag;
	bfd->discrs.remote_discr = 0;
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->polling = 0;
	bfd->demand_mode = 0;
	monotime(&bfd->downtime);

	/*
	 * Only attempt to send if we have a valid socket:
	 * this function might be called by session disablers and in
	 * this case we won't have a valid socket (i.e. interface was
	 * removed or VRF doesn't exist anymore).
	 */
	if (bfd->sock != -1)
		ptm_bfd_snd(bfd, 0);

	/* Slow down the control packets, the connection is down. */
	bs_set_slow_timers(bfd);

	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		ptm_bfd_notify(bfd, PTM_BFD_DOWN);

	/* Stop echo packet transmission if they are active */
	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
		ptm_bfd_echo_stop(bfd);

	/* Stop attempting to transmit or expect control packets if passive. */
	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_PASSIVE)) {
		bfd_recvtimer_delete(bfd);
		bfd_xmttimer_delete(bfd);
	}

	if (old_state != bfd->ses_state) {
		bfd->stats.session_down++;
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: [%s] %s -> %s reason:%s",
				   bs_to_string(bfd), state_list[old_state].str,
				   state_list[bfd->ses_state].str,
				   get_diag_str(bfd->local_diag));
		if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES) &&
		    old_state == PTM_BFD_UP)
			zlog_notice("Session-Change: [%s] %s -> %s reason:%s", bs_to_string(bfd),
				    state_list[old_state].str, state_list[bfd->ses_state].str,
				    get_diag_str(bfd->local_diag));
	}

	/* clear peer's mac address */
	UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_MAC_SET);
	memset(bfd->peer_hw_addr, 0, sizeof(bfd->peer_hw_addr));
	/* reset local address ,it might has been be changed after bfd is up*/
	if (bfd->bfd_mode == BFD_MODE_TYPE_BFD)
		memset(&bfd->local_address, 0, sizeof(bfd->local_address));

	/* reset RTT */
	bfd_rtt_init(bfd);
}

/*sbfd session up , include sbfd and sbfd echo*/
void ptm_sbfd_sess_up(struct bfd_session *bfd)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = 0;
	bfd->ses_state = PTM_BFD_UP;
	monotime(&bfd->uptime);

	/*notify session up*/
	ptm_bfd_notify(bfd, bfd->ses_state);

	if (old_state != bfd->ses_state) {
		bfd->stats.session_up++;
		if (bglobal.debug_peer_event)
			zlog_info("state-change: [%s] %s -> %s", bs_to_string(bfd),
				  state_list[old_state].str, state_list[bfd->ses_state].str);
		if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES))
			zlog_notice("Session-Change: [%s] %s -> %s", bs_to_string(bfd),
				    state_list[old_state].str, state_list[bfd->ses_state].str);
	}
}

/*sbfd init session TO */
void ptm_sbfd_init_sess_dn(struct bfd_session *bfd, uint8_t diag)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = diag;
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->polling = 0;
	bfd->demand_mode = 0;
	monotime(&bfd->downtime);

	/*
	 * Only attempt to send if we have a valid socket:
	 * this function might be called by session disablers and in
	 * this case we won't have a valid socket (i.e. interface was
	 * removed or VRF doesn't exist anymore).
	 */
	if (bfd->sock != -1)
		ptm_sbfd_init_reset(bfd);

	/* Slow down the control packets, the connection is down. */
	bs_set_slow_timers(bfd);

	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		ptm_bfd_notify(bfd, PTM_BFD_DOWN);

	/* Stop attempting to transmit or expect control packets if passive. */
	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_PASSIVE)) {
		sbfd_init_recvtimer_delete(bfd);
		sbfd_init_xmttimer_delete(bfd);
	}

	if (old_state != bfd->ses_state) {
		bfd->stats.session_down++;
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: [%s] %s -> %s reason:%s", bs_to_string(bfd),
				   state_list[old_state].str, state_list[bfd->ses_state].str,
				   get_diag_str(bfd->local_diag));
		if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES) &&
		    old_state == PTM_BFD_UP)
			zlog_notice("Session-Change: [%s] %s -> %s reason:%s", bs_to_string(bfd),
				    state_list[old_state].str, state_list[bfd->ses_state].str,
				    get_diag_str(bfd->local_diag));
	}
	/* reset local address ,it might has been be changed after bfd is up*/
	//memset(&bfd->local_address, 0, sizeof(bfd->local_address));
}

/*sbfd echo session TO */
void ptm_sbfd_echo_sess_dn(struct bfd_session *bfd, uint8_t diag)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = diag;
	bfd->discrs.remote_discr = 0;
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->polling = 0;
	bfd->demand_mode = 0;
	monotime(&bfd->downtime);
	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		ptm_bfd_notify(bfd, PTM_BFD_DOWN);

	ptm_sbfd_echo_reset(bfd);

	if (old_state != bfd->ses_state) {
		bfd->stats.session_down++;
		if (bglobal.debug_peer_event)
			zlog_warn("state-change: [%s] %s -> %s reason:%s", bs_to_string(bfd),
				  state_list[old_state].str, state_list[bfd->ses_state].str,
				  get_diag_str(bfd->local_diag));
		if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES) &&
		    old_state == PTM_BFD_UP)
			zlog_notice("Session-Change: [%s] %s -> %s reason:%s", bs_to_string(bfd),
				    state_list[old_state].str, state_list[bfd->ses_state].str,
				    get_diag_str(bfd->local_diag));
	}
}

static struct bfd_session *bfd_find_disc(struct sockaddr_any *sa,
					 uint32_t ldisc)
{
	return bfd_id_lookup(ldisc);
}

struct bfd_session *ptm_bfd_sess_find(struct bfd_pkt *cp,
				      struct sockaddr_any *peer,
				      struct sockaddr_any *local,
				      struct interface *ifp,
				      vrf_id_t vrfid,
				      bool is_mhop)
{
	struct vrf *vrf;
	struct bfd_key key;

	/* Find our session using the ID signaled by the remote end. */
	if (cp->discrs.remote_discr)
		return bfd_find_disc(peer, ntohl(cp->discrs.remote_discr));

	/* Search for session without using discriminator. */
	vrf = vrf_lookup_by_id(vrfid);

	gen_bfd_key(&key, peer, local, is_mhop, ifp ? ifp->name : NULL,
		    vrf ? vrf->name : VRF_DEFAULT_NAME, NULL);

	/* XXX maybe remoteDiscr should be checked for remoteHeard cases. */
	return bfd_key_lookup(&key);
}

void bfd_xmt_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	ptm_bfd_xmt_TO(bs, 0);
}

void bfd_echo_xmt_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (bs->echo_xmt_TO > 0)
		ptm_bfd_echo_xmt_TO(bs);
}

void sbfd_init_xmt_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	ptm_sbfd_init_xmt_TO(bs, 0);
}

void sbfd_echo_xmt_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (bs->echo_xmt_TO > 0)
		ptm_sbfd_echo_xmt_TO(bs);
}

/* Was ptm_bfd_detect_TO() */
void bfd_recvtimer_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	switch (bs->ses_state) {
	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		ptm_bfd_sess_dn(bs, BD_CONTROL_EXPIRED);
		break;
	}
}

/* Was ptm_bfd_echo_detect_TO() */
void bfd_echo_recvtimer_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (bglobal.debug_peer_event) {
		zlog_debug("%s:  time-out bfd: [%s]  bfd'state is %s", __func__, bs_to_string(bs),
			   state_list[bs->ses_state].str);
	}

	switch (bs->ses_state) {
	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		ptm_bfd_sess_dn(bs, BD_ECHO_FAILED);
		break;
	}
}

void sbfd_init_recvtimer_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	switch (bs->ses_state) {
	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		ptm_sbfd_init_sess_dn(bs, BD_PATH_DOWN);
		break;

	default:
		/* Second detect time expiration, zero remote discr (section
		 * 6.5.1)
		 */
		break;
	}
}
void sbfd_echo_recvtimer_cb(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (bglobal.debug_peer_event) {
		zlog_debug("%s:  time-out bfd: [%s]  bfd'state is %s", __func__, bs_to_string(bs),
			   state_list[bs->ses_state].str);
	}

	switch (bs->ses_state) {
	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		ptm_sbfd_echo_sess_dn(bs, BD_PATH_DOWN);
		break;
	case PTM_BFD_DOWN:
		break;
	}
}

struct bfd_session *bfd_session_new(enum bfd_mode_type mode)
{
	struct bfd_session *bs;

	bs = XCALLOC(MTYPE_BFDD_CONFIG, sizeof(struct bfd_session));
	bs->segnum = 0;
	bs->bfd_mode = mode;

	/* Set peer session defaults. */
	bfd_profile_set_default(&bs->peer_profile);

	bs->timers.desired_min_tx = BFD_DEFDESIREDMINTX;
	bs->timers.required_min_rx = BFD_DEFREQUIREDMINRX;
	bs->timers.required_min_echo_rx = BFD_DEF_REQ_MIN_ECHO_RX;
	bs->timers.desired_min_echo_tx = BFD_DEF_DES_MIN_ECHO_TX;
	bs->detect_mult = BFD_DEFDETECTMULT;
	bs->mh_ttl = BFD_DEF_MHOP_TTL;
	bs->ses_state = PTM_BFD_DOWN;

	/* Initiate connection with slow timers. */
	bs_set_slow_timers(bs);

	/* Initiate remote settings as well. */
	bs->remote_timers = bs->cur_timers;
	bs->remote_detect_mult = BFD_DEFDETECTMULT;

	bs->sock = -1;
	monotime(&bs->uptime);
	bs->downtime = bs->uptime;

	return bs;
}

static void _bfd_session_update(struct bfd_session *bs,
				struct bfd_peer_cfg *bpc)
{
	if (bpc->bpc_has_txinterval) {
		bs->timers.desired_min_tx = bpc->bpc_txinterval * 1000;
		bs->peer_profile.min_tx = bs->timers.desired_min_tx;
	}

	if (bpc->bpc_has_recvinterval) {
		bs->timers.required_min_rx = bpc->bpc_recvinterval * 1000;
		bs->peer_profile.min_rx = bs->timers.required_min_rx;
	}

	if (bpc->bpc_has_detectmultiplier) {
		bs->detect_mult = bpc->bpc_detectmultiplier;
		bs->peer_profile.detection_multiplier = bs->detect_mult;
	}

	if (bpc->bpc_has_echorecvinterval) {
		bs->timers.required_min_echo_rx = bpc->bpc_echorecvinterval * 1000;
		bs->peer_profile.min_echo_rx = bs->timers.required_min_echo_rx;
	}

	if (bpc->bpc_has_echotxinterval) {
		bs->timers.desired_min_echo_tx = bpc->bpc_echotxinterval * 1000;
		bs->peer_profile.min_echo_tx = bs->timers.desired_min_echo_tx;
	}

	if (bpc->bpc_cbit)
		SET_FLAG(bs->flags, BFD_SESS_FLAG_CBIT);
	else
		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_CBIT);

	if (bpc->bpc_has_minimum_ttl) {
		bs->mh_ttl = bpc->bpc_minimum_ttl;
		bs->peer_profile.minimum_ttl = bpc->bpc_minimum_ttl;
	}

	bs->peer_profile.echo_mode = bpc->bpc_echo;
	bfd_set_echo(bs, bpc->bpc_echo);

	if (bpc->bpc_log_session_changes)
		SET_FLAG(bs->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES);
	else
		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES);

	/*
	 * Shutdown needs to be the last in order to avoid timers enable when
	 * the session is disabled.
	 */
	bs->peer_profile.admin_shutdown = bpc->bpc_shutdown;
	bfd_set_passive_mode(bs, bpc->bpc_passive);
	bfd_set_shutdown(bs, bpc->bpc_shutdown);

	/*
	 * Apply profile last: it also calls `bfd_set_shutdown`.
	 *
	 * There is no problem calling `shutdown` twice if the value doesn't
	 * change or if it is overridden by peer specific configuration.
	 */
	if (bpc->bpc_has_profile)
		bfd_profile_apply(bpc->bpc_profile, bs);
}

static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc)
{
	/* User didn't want to update, return failure. */
	if (bpc->bpc_createonly)
		return -1;

	_bfd_session_update(bs, bpc);

	return 0;
}

void bfd_session_free(struct bfd_session *bs)
{
	struct bfd_session_observer *bso;

	bfd_session_disable(bs);

	/* Remove session from data plane if any. */
	bfd_dplane_delete_session(bs);

	bfd_key_delete(&bs->key);
	bfd_id_delete(bs->discrs.my_discr);

	/* Remove observer if any. */
	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		if (bso->bso_bs != bs)
			continue;

		break;
	}
	if (bso != NULL)
		bs_observer_del(bso);

	XFREE(MTYPE_BFDD_PROFILE, bs->profile_name);
	XFREE(MTYPE_BFDD_CONFIG, bs);
}

struct bfd_session *ptm_bfd_sess_new(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bfd, *l_bfd;

	/* check to see if this needs a new session */
	l_bfd = bs_peer_find(bpc);
	if (l_bfd) {
		/* Requesting a duplicated peer means update configuration. */
		if (bfd_session_update(l_bfd, bpc) == 0)
			return l_bfd;
		else
			return NULL;
	}

	/* Get BFD session storage with its defaults. */
	bfd = bfd_session_new(BFD_MODE_TYPE_BFD);

	/*
	 * Store interface/VRF name in case we need to delay session
	 * start. See `bfd_session_enable` for more information.
	 */
	if (bpc->bpc_has_localif)
		strlcpy(bfd->key.ifname, bpc->bpc_localif,
			sizeof(bfd->key.ifname));

	if (bpc->bpc_has_vrfname)
		strlcpy(bfd->key.vrfname, bpc->bpc_vrfname,
			sizeof(bfd->key.vrfname));
	else
		strlcpy(bfd->key.vrfname, VRF_DEFAULT_NAME,
			sizeof(bfd->key.vrfname));

	/* Copy remaining data. */
	if (bpc->bpc_ipv4 == false)
		SET_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6);

	bfd->key.family = (bpc->bpc_ipv4) ? AF_INET : AF_INET6;
	switch (bfd->key.family) {
	case AF_INET:
		memcpy(&bfd->key.peer, &bpc->bpc_peer.sa_sin.sin_addr,
		       sizeof(bpc->bpc_peer.sa_sin.sin_addr));
		memcpy(&bfd->key.local, &bpc->bpc_local.sa_sin.sin_addr,
		       sizeof(bpc->bpc_local.sa_sin.sin_addr));
		break;

	case AF_INET6:
		memcpy(&bfd->key.peer, &bpc->bpc_peer.sa_sin6.sin6_addr,
		       sizeof(bpc->bpc_peer.sa_sin6.sin6_addr));
		memcpy(&bfd->key.local, &bpc->bpc_local.sa_sin6.sin6_addr,
		       sizeof(bpc->bpc_local.sa_sin6.sin6_addr));
		break;

	default:
		assert(1);
		break;
	}

	if (bpc->bpc_mhop)
		SET_FLAG(bfd->flags, BFD_SESS_FLAG_MH);

	bfd->key.mhop = bpc->bpc_mhop;

	if (bs_registrate(bfd) == NULL)
		return NULL;

	/* Apply other configurations. */
	_bfd_session_update(bfd, bpc);

	return bfd;
}

struct bfd_session *bs_registrate(struct bfd_session *bfd)
{
	/* Registrate session into data structures. */
	bfd_key_insert(bfd);
	bfd->discrs.my_discr = ptm_bfd_gen_ID();
	bfd_id_insert(bfd);

	/* Try to enable session and schedule for packet receive/send. */
	if (bfd_session_enable(bfd) == -1) {
		/* Unrecoverable failure, remove the session/peer. */
		bfd_session_free(bfd);
		return NULL;
	}

	/* Add observer if we have moving parts. */
	if (bfd->key.ifname[0] || bfd->key.vrfname[0] || bfd->sock == -1)
		bs_observer_add(bfd);

	if (bglobal.debug_peer_event)
		zlog_debug("session-new: %s", bs_to_string(bfd));

	return bfd;
}

int ptm_bfd_sess_del(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bs;

	/* Find session and call free(). */
	bs = bs_peer_find(bpc);
	if (bs == NULL)
		return -1;

	/* This pointer is being referenced, don't let it be deleted. */
	if (bs->refcount > 0) {
		zlog_err("session-delete: refcount failure: %" PRIu64" references",
			 bs->refcount);
		return -1;
	}

	if (bglobal.debug_peer_event)
		zlog_debug("%s: %s", __func__, bs_to_string(bs));

	bfd_session_free(bs);

	return 0;
}

void bfd_set_polling(struct bfd_session *bs)
{
	/*
	 * Start polling procedure: the only timers that require polling
	 * to change value without losing connection are:
	 *
	 *   - Desired minimum transmission interval;
	 *   - Required minimum receive interval;
	 *
	 * RFC 5880, Section 6.8.3.
	 */
	bs->polling = 1;
}

/*
 * bs_<state>_handler() functions implement the BFD state machine
 * transition mechanism. `<state>` is the current session state and
 * the parameter `nstate` is the peer new state.
 */
static void bs_admin_down_handler(struct bfd_session *bs
				  __attribute__((__unused__)),
				  int nstate __attribute__((__unused__)))
{
	/*
	 * We are administratively down, there is no state machine
	 * handling.
	 */
}

static void bs_down_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
		/*
		 * Remote peer doesn't want to talk, so lets keep the
		 * connection down.
		 */
	case PTM_BFD_UP:
		/* Peer can't be up yet, wait it go to 'init' or 'down'. */
		break;

	case PTM_BFD_DOWN:
		/*
		 * Remote peer agreed that the path is down, lets try to
		 * bring it up.
		 */
		bs->ses_state = PTM_BFD_INIT;

		/*
		 * RFC 5880, Section 6.1.
		 * A system taking the Passive role MUST NOT begin
		 * sending BFD packets for a particular session until
		 * it has received a BFD packet for that session, and thus
		 * has learned the remote system's discriminator value.
		 *
		 * Now we can start transmission timer in passive mode.
		 */
		if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE))
			ptm_bfd_xmt_TO(bs, 0);

		break;

	case PTM_BFD_INIT:
		/*
		 * Remote peer told us his path is up, lets turn
		 * activate the session.
		 */
		ptm_bfd_sess_up(bs);
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: unhandled neighbor state: %d",
				   nstate);
		break;
	}
}

static void sbfd_down_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
		/*
		 * Remote peer doesn't want to talk, so lets keep the
		 * connection down.
		 */
		break;
	case PTM_BFD_UP:
		/* down - > up*/
		ptm_sbfd_sess_up(bs);
		break;

	case PTM_BFD_DOWN:
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_err("state-change: unhandled sbfd state: %d", nstate);
		break;
	}
}

static void bs_init_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
		/*
		 * Remote peer doesn't want to talk, so lets make the
		 * connection down.
		 */
		ptm_bfd_sess_dn(bs, BD_NEIGHBOR_DOWN);
		break;

	case PTM_BFD_DOWN:
		/* Remote peer hasn't moved to first stage yet. */
		break;

	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		/* We agreed on the settings and the path is up. */
		ptm_bfd_sess_up(bs);
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: unhandled neighbor state: %d",
				   nstate);
		break;
	}
}

static void bs_up_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
	case PTM_BFD_DOWN:
		/* Peer lost or asked to shutdown connection. */
		ptm_bfd_sess_dn(bs, BD_NEIGHBOR_DOWN);
		break;

	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		/* Path is up and working. */
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: unhandled neighbor state: %d",
				   nstate);
		break;
	}
}

static void sbfd_up_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
	case PTM_BFD_DOWN:
		if (bs->bfd_mode == BFD_MODE_TYPE_SBFD_ECHO) {
			ptm_sbfd_echo_sess_dn(bs, BD_ECHO_FAILED);
		} else
			ptm_sbfd_init_sess_dn(bs, BD_ECHO_FAILED);

		break;

	case PTM_BFD_UP:
		/* Path is up and working. */
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: unhandled neighbor state: %d", nstate);
		break;
	}
}

void bs_state_handler(struct bfd_session *bs, int nstate)
{
	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		bs_admin_down_handler(bs, nstate);
		break;
	case PTM_BFD_DOWN:
		bs_down_handler(bs, nstate);
		break;
	case PTM_BFD_INIT:
		bs_init_handler(bs, nstate);
		break;
	case PTM_BFD_UP:
		bs_up_handler(bs, nstate);
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: [%s] is in invalid state: %d",
				   bs_to_string(bs), nstate);
		break;
	}
}

void sbfd_echo_state_handler(struct bfd_session *bs, int nstate)
{
	if (bglobal.debug_peer_event)
		zlog_debug("%s:  bfd(%u) state: %s , notify state: %s", __func__,
			   bs->discrs.my_discr, state_list[bs->ses_state].str,
			   state_list[nstate].str);

	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		// bs_admin_down_handler(bs, nstate);
		break;
	case PTM_BFD_DOWN:
		sbfd_down_handler(bs, nstate);
		break;
	case PTM_BFD_UP:
		sbfd_up_handler(bs, nstate);
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: [%s] is in invalid state: %d", bs_to_string(bs),
				   nstate);
		break;
	}
}

void sbfd_initiator_state_handler(struct bfd_session *bs, int nstate)
{
	if (bglobal.debug_peer_event)
		zlog_debug("%s:  sbfd(%u) state: %s , notify state: %s", __func__,
			   bs->discrs.my_discr, state_list[bs->ses_state].str,
			   state_list[nstate].str);

	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		// bs_admin_down_handler(bs, nstate);
		break;
	case PTM_BFD_DOWN:
		sbfd_down_handler(bs, nstate);
		break;
	case PTM_BFD_UP:
		sbfd_up_handler(bs, nstate);
		break;

	default:
		if (bglobal.debug_peer_event)
			zlog_debug("state-change: [%s] is in invalid state: %d", bs_to_string(bs),
				   nstate);
		break;
	}
}

/*
 * Handles echo timer manipulation after updating timer.
 */
void bs_echo_timer_handler(struct bfd_session *bs)
{
	uint32_t old_timer;

	/*
	 * Before doing any echo handling, check if it is possible to
	 * use it.
	 *
	 *   - Check for `echo-mode` configuration.
	 *   - Check that we are not using multi hop (RFC 5883,
	 *     Section 3).
	 *   - Check that we are already at the up state.
	 */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO) == 0
	    || CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)
	    || bs->ses_state != PTM_BFD_UP)
		return;

	/* Remote peer asked to stop echo. */
	if (bs->remote_timers.required_min_echo == 0) {
		if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
			ptm_bfd_echo_stop(bs);

		return;
	}

	/*
	 * Calculate the echo transmission timer: we must not send
	 * echo packets faster than the minimum required time
	 * announced by the remote system.
	 *
	 * RFC 5880, Section 6.8.9.
	 */
	old_timer = bs->echo_xmt_TO;
	if (bs->remote_timers.required_min_echo > bs->timers.desired_min_echo_tx)
		bs->echo_xmt_TO = bs->remote_timers.required_min_echo;
	else
		bs->echo_xmt_TO = bs->timers.desired_min_echo_tx;

	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO_ACTIVE) == 0
	    || old_timer != bs->echo_xmt_TO)
		ptm_bfd_echo_start(bs);
}

/*
 * RFC 5880 Section 6.5.
 *
 * When a BFD control packet with the final bit is received, we must
 * update the session parameters.
 */
void bs_final_handler(struct bfd_session *bs)
{
	uint64_t old_xmt_TO = bs->xmt_TO;

	/* Start using our new timers. */
	bs->cur_timers.desired_min_tx = bs->timers.desired_min_tx;
	bs->cur_timers.required_min_rx = bs->timers.required_min_rx;

	/*
	 * TODO: demand mode. See RFC 5880 Section 6.1.
	 *
	 * When using demand mode we must disable the detection timer
	 * for lost control packets.
	 */
	if (bs->demand_mode)
		return;

	/*
	 * Calculate transmission time based on new timers.
	 *
	 * Transmission calculation:
	 * Unless specified by exceptions at the end of Section 6.8.7, the
	 * transmission time will be determined by the system with the
	 * slowest rate.
	 *
	 * RFC 5880, Section 6.8.7.
	 */
	if (bs->timers.desired_min_tx > bs->remote_timers.required_min_rx)
		bs->xmt_TO = bs->timers.desired_min_tx;
	else
		bs->xmt_TO = bs->remote_timers.required_min_rx;
	
	/* Only apply increased transmission interval after Poll Sequence */
	if (bs->ses_state == PTM_BFD_UP && bs->xmt_TO > old_xmt_TO) {
		bs->xmt_TO = old_xmt_TO;  /* Keep old timing until Poll Sequence done */
		return;
	}

	/* Apply new transmission timer immediately. */
	ptm_bfd_start_xmt_timer(bs, false);
}

void bs_set_slow_timers(struct bfd_session *bs)
{
	/*
	 * BFD connection must use slow timers before going up or after
	 * losing connectivity to avoid wasting bandwidth.
	 *
	 * RFC 5880, Section 6.8.3.
	 */
	bs->cur_timers.desired_min_tx = BFD_DEF_SLOWTX;
	bs->cur_timers.required_min_rx = BFD_DEF_SLOWTX;
	bs->cur_timers.required_min_echo = 0;

	/* Set the appropriated timeouts for slow connection. */
	bs->detect_TO = (BFD_DEFDETECTMULT * BFD_DEF_SLOWTX);
	bs->xmt_TO = BFD_DEF_SLOWTX;

	/* add for sbfd-echo slow connection  */
	if (BFD_MODE_TYPE_SBFD_ECHO == bs->bfd_mode) {
		bs->echo_xmt_TO = SBFD_ECHO_DEF_SLOWTX;
		bs->timers.desired_min_echo_tx = BFD_DEFDESIREDMINTX;
		bs->timers.required_min_echo_rx = BFD_DEFDESIREDMINTX;
		bs->peer_profile.min_echo_rx = BFD_DEFDESIREDMINTX;
		bs->peer_profile.min_echo_tx = BFD_DEFDESIREDMINTX;
	}
}

void bfd_set_echo(struct bfd_session *bs, bool echo)
{
	if (echo) {
		/* Check if echo mode is already active. */
		if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			return;

		SET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);

		/* Activate/update echo receive timeout timer. */
		if (bs->bdc == NULL)
			bs_echo_timer_handler(bs);
	} else {
		/* Check if echo mode is already disabled. */
		if (!CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			return;

		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);

		/* Deactivate timeout timer. */
		if (bs->bdc == NULL)
			ptm_bfd_echo_stop(bs);
	}

	if (bs->vrf && bs->vrf->info)
		bfd_vrf_toggle_echo(bs->vrf->info);
}

void bfd_set_shutdown(struct bfd_session *bs, bool shutdown)
{
	bool is_shutdown;

	/*
	 * Special case: we are batching changes and the previous state was
	 * not shutdown. Instead of potentially disconnect a running peer,
	 * we'll get the current status to validate we were really down.
	 */
	if (bs->ses_state == PTM_BFD_UP)
		is_shutdown = false;
	else
		is_shutdown = CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);

	if (shutdown) {
		/* Already shutdown. */
		if (is_shutdown)
			return;

		SET_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);
		bs->local_diag = BD_ADMIN_DOWN;

		/* Handle data plane shutdown case. */
		if (bs->bdc) {
			bs->ses_state = PTM_BFD_ADM_DOWN;
			bfd_dplane_update_session(bs);
			ptm_bfd_notify(bs, bs->ses_state);
			return;
		}

		/* Disable all events. */
		bfd_recvtimer_delete(bs);
		bfd_echo_recvtimer_delete(bs);
		bfd_xmttimer_delete(bs);
		bfd_echo_xmttimer_delete(bs);

		/* Change and notify state change. */
		bs->ses_state = PTM_BFD_ADM_DOWN;
		ptm_bfd_notify(bs, bs->ses_state);

		/* Don't try to send packets with a disabled session. */
		if (bs->sock != -1)
			ptm_bfd_snd(bs, 0);
	} else {
		/* Already working. */
		if (!is_shutdown)
			return;

		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);

		/* Handle data plane shutdown case. */
		if (bs->bdc) {
			bs->ses_state = PTM_BFD_DOWN;
			bfd_dplane_update_session(bs);
			ptm_bfd_notify(bs, bs->ses_state);
			return;
		}

		/* Change and notify state change. */
		bs->ses_state = PTM_BFD_DOWN;
		ptm_bfd_notify(bs, bs->ses_state);

		/* Enable timers if non passive, otherwise stop them. */
		if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE)) {
			bfd_recvtimer_delete(bs);
			bfd_xmttimer_delete(bs);
		} else {
			bfd_recvtimer_update(bs);
			bfd_xmttimer_update(bs, bs->xmt_TO);
		}
	}
}

void bfd_set_passive_mode(struct bfd_session *bs, bool passive)
{
	if (passive) {
		SET_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE);

		/* Session is already up and running, nothing to do now. */
		if (bs->ses_state != PTM_BFD_DOWN)
			return;

		/* Lets disable the timers since we are now passive. */
		bfd_recvtimer_delete(bs);
		bfd_xmttimer_delete(bs);
	} else {
		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE);

		/* Session is already up and running, nothing to do now. */
		if (bs->ses_state != PTM_BFD_DOWN)
			return;

		/* Session is down, let it attempt to start the connection. */
		bfd_xmttimer_update(bs, bs->xmt_TO);
		bfd_recvtimer_update(bs);
	}
}

void bfd_set_log_session_changes(struct bfd_session *bs, bool log_session_changes)
{
	if (log_session_changes)
		SET_FLAG(bs->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES);
	else
		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_LOG_SESSION_CHANGES);
}

/*
 * Helper functions.
 */
static const char *get_diag_str(int diag)
{
	for (int i = 0; diag_list[i].str; i++) {
		if (diag_list[i].type == diag)
			return diag_list[i].str;
	}
	return "N/A";
}

const char *satostr(const struct sockaddr_any *sa)
{
#define INETSTR_BUFCOUNT 8
	static char buf[INETSTR_BUFCOUNT][INET6_ADDRSTRLEN];
	static int bufidx;
	const struct sockaddr_in *sin = &sa->sa_sin;
	const struct sockaddr_in6 *sin6 = &sa->sa_sin6;

	bufidx += (bufidx + 1) % INETSTR_BUFCOUNT;
	buf[bufidx][0] = 0;

	switch (sin->sin_family) {
	case AF_INET:
		inet_ntop(AF_INET, &sin->sin_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;

	default:
		strlcpy(buf[bufidx], "unknown", sizeof(buf[bufidx]));
		break;
	}

	return buf[bufidx];
}

const char *diag2str(uint8_t diag)
{
	switch (diag) {
	case 0:
		return "ok";
	case 1:
		return "control detection time expired";
	case 2:
		return "echo function failed";
	case 3:
		return "neighbor signaled session down";
	case 4:
		return "forwarding plane reset";
	case 5:
		return "path down";
	case 6:
		return "concatenated path down";
	case 7:
		return "administratively down";
	case 8:
		return "reverse concatenated path down";
	default:
		return "unknown";
	}
}

int strtosa(const char *addr, struct sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));

	if (inet_pton(AF_INET, addr, &sa->sa_sin.sin_addr) == 1) {
		sa->sa_sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sa->sa_sin.sin_len = sizeof(sa->sa_sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return 0;
	}

	if (inet_pton(AF_INET6, addr, &sa->sa_sin6.sin6_addr) == 1) {
		sa->sa_sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sa->sa_sin6.sin6_len = sizeof(sa->sa_sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return 0;
	}

	return -1;
}

void integer2timestr(uint64_t time, char *buf, size_t buflen)
{
	uint64_t year, month, day, hour, minute, second;
	int rv;

#define MINUTES (60)
#define HOURS (60 * MINUTES)
#define DAYS (24 * HOURS)
#define MONTHS (30 * DAYS)
#define YEARS (12 * MONTHS)
	if (time >= YEARS) {
		year = time / YEARS;
		time -= year * YEARS;

		rv = snprintfrr(buf, buflen, "%" PRIu64 " year(s), ", year);
		buf += rv;
		buflen -= rv;
	}
	if (time >= MONTHS) {
		month = time / MONTHS;
		time -= month * MONTHS;

		rv = snprintfrr(buf, buflen, "%" PRIu64 " month(s), ", month);
		buf += rv;
		buflen -= rv;
	}
	if (time >= DAYS) {
		day = time / DAYS;
		time -= day * DAYS;

		rv = snprintfrr(buf, buflen, "%" PRIu64 " day(s), ", day);
		buf += rv;
		buflen -= rv;
	}
	if (time >= HOURS) {
		hour = time / HOURS;
		time -= hour * HOURS;

		rv = snprintfrr(buf, buflen, "%" PRIu64 " hour(s), ", hour);
		buf += rv;
		buflen -= rv;
	}
	if (time >= MINUTES) {
		minute = time / MINUTES;
		time -= minute * MINUTES;

		rv = snprintfrr(buf, buflen, "%" PRIu64 " minute(s), ", minute);
		buf += rv;
		buflen -= rv;
	}
	second = time % MINUTES;
	snprintfrr(buf, buflen, "%" PRIu64 " second(s)", second);
}

const char *bs_to_string(const struct bfd_session *bs)
{
	static char buf[256];
	char addr_buf[INET6_ADDRSTRLEN];
	int pos;
	bool is_mhop = CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH);

	pos = snprintf(buf, sizeof(buf), "mhop:%s", is_mhop ? "yes" : "no");
	pos += snprintf(buf + pos, sizeof(buf) - pos, " peer:%s",
			inet_ntop(bs->key.family, &bs->key.peer, addr_buf,
				  sizeof(addr_buf)));
	pos += snprintf(buf + pos, sizeof(buf) - pos, " local:%s",
			inet_ntop(bs->key.family, &bs->key.local, addr_buf,
				  sizeof(addr_buf)));
	if (bs->key.vrfname[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " vrf:%s",
				bs->key.vrfname);
	if (bs->key.ifname[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " ifname:%s",
				bs->key.ifname);
	if (bs->bfd_name[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " bfd_name:%s", bs->bfd_name);

	(void)pos;

	return buf;
}

int bs_observer_add(struct bfd_session *bs)
{
	struct bfd_session_observer *bso;

	bso = XCALLOC(MTYPE_BFDD_SESSION_OBSERVER, sizeof(*bso));
	bso->bso_bs = bs;
	bso->bso_addr.family = bs->key.family;
	memcpy(&bso->bso_addr.u.prefix, &bs->key.local,
	       sizeof(bs->key.local));

	TAILQ_INSERT_TAIL(&bglobal.bg_obslist, bso, bso_entry);

	return 0;
}

void bs_observer_del(struct bfd_session_observer *bso)
{
	TAILQ_REMOVE(&bglobal.bg_obslist, bso, bso_entry);
	XFREE(MTYPE_BFDD_SESSION_OBSERVER, bso);
}

void bs_to_bpc(struct bfd_session *bs, struct bfd_peer_cfg *bpc)
{
	memset(bpc, 0, sizeof(*bpc));

	bpc->bpc_ipv4 = (bs->key.family == AF_INET);
	bpc->bpc_mhop = bs->key.mhop;

	switch (bs->key.family) {
	case AF_INET:
		bpc->bpc_peer.sa_sin.sin_family = AF_INET;
		memcpy(&bpc->bpc_peer.sa_sin.sin_addr, &bs->key.peer,
		       sizeof(bpc->bpc_peer.sa_sin.sin_addr));

		if (memcmp(&bs->key.local, &zero_addr, sizeof(bs->key.local))) {
			bpc->bpc_local.sa_sin.sin_family = AF_INET6;
			memcpy(&bpc->bpc_local.sa_sin.sin_addr, &bs->key.local,
			       sizeof(bpc->bpc_local.sa_sin.sin_addr));
		}
		break;

	case AF_INET6:
		bpc->bpc_peer.sa_sin.sin_family = AF_INET6;
		memcpy(&bpc->bpc_peer.sa_sin6.sin6_addr, &bs->key.peer,
		       sizeof(bpc->bpc_peer.sa_sin6.sin6_addr));

		bpc->bpc_local.sa_sin6.sin6_family = AF_INET6;
		memcpy(&bpc->bpc_local.sa_sin6.sin6_addr, &bs->key.local,
		       sizeof(bpc->bpc_local.sa_sin6.sin6_addr));
		break;
	}

	if (bs->key.ifname[0]) {
		bpc->bpc_has_localif = true;
		strlcpy(bpc->bpc_localif, bs->key.ifname,
			sizeof(bpc->bpc_localif));
	}

	if (bs->key.vrfname[0]) {
		bpc->bpc_has_vrfname = true;
		strlcpy(bpc->bpc_vrfname, bs->key.vrfname,
			sizeof(bpc->bpc_vrfname));
	}
}


/*
 * BFD hash data structures to find sessions.
 */
static struct hash *bfd_id_hash;
static struct hash *bfd_key_hash;

/*sbfd reflector discr hash*/
static struct hash *sbfd_rflt_hash;
static unsigned int sbfd_discr_hash_do(const void *p);

static unsigned int bfd_id_hash_do(const void *p);
static unsigned int bfd_key_hash_do(const void *p);

static void _bfd_free(struct hash_bucket *hb,
		      void *arg __attribute__((__unused__)));

/* BFD hash for our discriminator. */
static unsigned int bfd_id_hash_do(const void *p)
{
	const struct bfd_session *bs = p;

	return jhash_1word(bs->discrs.my_discr, 0);
}

static bool bfd_id_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return bs1->discrs.my_discr == bs2->discrs.my_discr;
}

/* BFD hash for single hop. */
static unsigned int bfd_key_hash_do(const void *p)
{
	const struct bfd_session *bs = p;
	struct bfd_key key = bs->key;

	/*
	 * Local address and interface name are optional and
	 * can be filled any time after session creation.
	 * Hash key should not depend on these fields.
	 */
	memset(&key.local, 0, sizeof(key.local));
	memset(key.ifname, 0, sizeof(key.ifname));

	return jhash(&key, sizeof(key), 0);
}

static bool bfd_key_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	if (bs1->key.family != bs2->key.family)
		return false;
	if (bs1->key.mhop != bs2->key.mhop)
		return false;
	if (memcmp(&bs1->key.peer, &bs2->key.peer, sizeof(bs1->key.peer)))
		return false;
	if (memcmp(bs1->key.vrfname, bs2->key.vrfname,
		   sizeof(bs1->key.vrfname)))
		return false;
	if (memcmp(bs1->key.bfdname, bs2->key.bfdname, sizeof(bs1->key.bfdname)))
		return false;

	/*
	 * Local address is optional and can be empty.
	 * If both addresses are not empty and different,
	 * then the keys are different.
	 */
	if (memcmp(&bs1->key.local, &zero_addr, sizeof(bs1->key.local))
	    && memcmp(&bs2->key.local, &zero_addr, sizeof(bs2->key.local))
	    && memcmp(&bs1->key.local, &bs2->key.local, sizeof(bs1->key.local)))
		return false;

	/*
	 * Interface name is optional and can be empty.
	 * If both names are not empty and different,
	 * then the keys are different.
	 */
	if (bs1->key.ifname[0] && bs2->key.ifname[0]
	    && memcmp(bs1->key.ifname, bs2->key.ifname,
		      sizeof(bs1->key.ifname)))
		return false;

	return true;
}

/* SBFD disr hash . */
static unsigned int sbfd_discr_hash_do(const void *p)
{
	const struct sbfd_reflector *sr = p;

	return jhash_1word(sr->discr, 0);
}

static bool sbfd_discr_hash_cmp(const void *n1, const void *n2)
{
	const struct sbfd_reflector *sr1 = n1, *sr2 = n2;

	return sr1->discr == sr2->discr;
}

/*
 * BFD permitted vrfs data structures.
 */
static unsigned int bfd_perm_vrfs_hash_do(const struct bfd_perm_vrf *vrf)
{
	return string_hash_make(vrf->vrf_name);
}

static bool bfd_perm_vrfs_hash_cmp(const struct bfd_perm_vrf *vrf1, const struct bfd_perm_vrf *vrf2)
{
	return strmatch(vrf1->vrf_name, vrf2->vrf_name);
}

/*
 * Hash public interface / exported functions.
 */

/* Lookup functions. */
struct bfd_session *bfd_id_lookup(uint32_t id)
{
	struct bfd_session bs;

	bs.discrs.my_discr = id;

	return hash_lookup(bfd_id_hash, &bs);
}

struct bfd_session *bfd_key_lookup(struct bfd_key *key)
{
	struct bfd_session bs;

	bs.key = *key;

	return hash_lookup(bfd_key_hash, &bs);
}

struct sbfd_reflector *sbfd_discr_lookup(uint32_t discr)
{
	struct sbfd_reflector sr;

	sr.discr = discr;

	return hash_lookup(sbfd_rflt_hash, &sr);
}

static struct bfd_perm_vrf *_bfd_perm_vrf_find(const char *vrf_name)
{
	struct bfd_perm_vrf ref = { .vrf_name = (char *)vrf_name };

	return bfd_perm_vrfs_find(&bfd_perm_vrfs, &ref);
}

/*
 * Delete functions.
 *
 * Delete functions searches and remove the item from the hash and
 * returns a pointer to the removed item data. If the item was not found
 * then it returns NULL.
 *
 * The data stored inside the hash is not free()ed, so you must do it
 * manually after getting the pointer back.
 */
struct bfd_session *bfd_id_delete(uint32_t id)
{
	struct bfd_session bs;

	bs.discrs.my_discr = id;

	return hash_release(bfd_id_hash, &bs);
}

struct bfd_session *bfd_key_delete(struct bfd_key *key)
{
	struct bfd_session bs;

	bs.key = *key;

	return hash_release(bfd_key_hash, &bs);
}

struct sbfd_reflector *sbfd_discr_delete(uint32_t discr)
{
	struct sbfd_reflector sr;

	sr.discr = discr;

	return hash_release(sbfd_rflt_hash, &sr);
}

/* Iteration functions. */
void bfd_id_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_id_hash, hif, arg);
}

void bfd_key_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_key_hash, hif, arg);
}

void sbfd_discr_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(sbfd_rflt_hash, hif, arg);
}

/*
 * Insert functions.
 *
 * Inserts session into hash and returns `true` on success, otherwise
 * `false`.
 */
bool bfd_id_insert(struct bfd_session *bs)
{
	return (hash_get(bfd_id_hash, bs, hash_alloc_intern) == bs);
}

bool bfd_key_insert(struct bfd_session *bs)
{
	return (hash_get(bfd_key_hash, bs, hash_alloc_intern) == bs);
}

bool sbfd_discr_insert(struct sbfd_reflector *sr)
{
	return (hash_get(sbfd_rflt_hash, sr, hash_alloc_intern) == sr);
}

unsigned long sbfd_discr_get_count(void)
{
	return sbfd_rflt_hash->count;
}

void bfd_initialize(void)
{
	bfd_id_hash = hash_create(bfd_id_hash_do, bfd_id_hash_cmp,
				  "BFD session discriminator hash");
	bfd_key_hash = hash_create(bfd_key_hash_do, bfd_key_hash_cmp,
				   "BFD session hash");
	sbfd_rflt_hash = hash_create(sbfd_discr_hash_do, sbfd_discr_hash_cmp,
				     "SBFD reflector discriminator hash");
	TAILQ_INIT(&bplist);
}

static void _bfd_free(struct hash_bucket *hb,
		      void *arg __attribute__((__unused__)))
{
	struct bfd_session *bs = hb->data;

	bfd_session_free(bs);
}

static void _sbfd_reflector_free(struct hash_bucket *hb, void *arg __attribute__((__unused__)))
{
	struct sbfd_reflector *sr = hb->data;


	sbfd_reflector_free(sr->discr);
}

void bfd_shutdown(void)
{
	struct bfd_profile *bp;

	/*
	 * Close and free all BFD sessions.
	 *
	 * _bfd_free() will call bfd_session_free() which will take care
	 * of removing the session from all hashes, so we just run an
	 * assert() here to make sure it really happened.
	 */
	bfd_id_iterate(_bfd_free, NULL);
	assert(bfd_key_hash->count == 0);

	sbfd_discr_iterate(_sbfd_reflector_free, NULL);
	assert(sbfd_rflt_hash->count == 0);

	/* Now free the hashes themselves. */
	hash_free(bfd_id_hash);
	hash_free(bfd_key_hash);
	hash_free(sbfd_rflt_hash);

	destroy_bfd_perm_vrfs_data();

	/* Free all profile allocations. */
	while ((bp = TAILQ_FIRST(&bplist)) != NULL)
		bfd_profile_free(bp);
}

struct bfd_session_iterator {
	int bsi_stop;
	bool bsi_mhop;
	uint32_t bsi_bfdmode;
	const struct bfd_session *bsi_bs;
};

static int _bfd_session_next(struct hash_bucket *hb, void *arg)
{
	struct bfd_session_iterator *bsi = arg;
	struct bfd_session *bs = hb->data;

	/* Previous entry signaled stop. */
	if (bsi->bsi_stop == 1) {
		/* Match the single/multi hop sessions. */
		if ((bs->key.mhop != bsi->bsi_mhop) || (bs->bfd_mode != bsi->bsi_bfdmode))
			return HASHWALK_CONTINUE;

		bsi->bsi_bs = bs;
		return HASHWALK_ABORT;
	}

	/* We found the current item, stop in the next one. */
	if (bsi->bsi_bs == hb->data) {
		bsi->bsi_stop = 1;
		/* Set entry to NULL to signal end of list. */
		bsi->bsi_bs = NULL;
	} else if (bsi->bsi_bs == NULL && bsi->bsi_mhop == bs->key.mhop &&
		   bsi->bsi_bfdmode == bs->bfd_mode) {
		/* We want the first list item. */
		bsi->bsi_stop = 1;
		bsi->bsi_bs = hb->data;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

/*
 * bfd_session_next: uses the current session to find the next.
 *
 * `bs` might point to NULL to get the first item of the data structure.
 */
const struct bfd_session *bfd_session_next(const struct bfd_session *bs, bool mhop,
					   uint32_t bfd_mode)
{
	struct bfd_session_iterator bsi;

	bsi.bsi_stop = 0;
	bsi.bsi_bs = bs;
	bsi.bsi_mhop = mhop;
	bsi.bsi_bfdmode = bfd_mode;
	hash_walk(bfd_key_hash, _bfd_session_next, &bsi);
	if (bsi.bsi_stop == 0)
		return NULL;

	return bsi.bsi_bs;
}

static void _bfd_session_remove_manual(struct hash_bucket *hb,
				       void *arg __attribute__((__unused__)))
{
	struct bfd_session *bs = hb->data;

	/* Delete only manually configured sessions. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG) == 0)
		return;

	bs->refcount--;
	UNSET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);

	/* Don't delete sessions still in use. */
	if (bs->refcount != 0)
		return;

	bfd_session_free(bs);
}

/*
 * bfd_sessions_remove_manual: remove all manually configured sessions.
 *
 * NOTE: this function doesn't remove automatically created sessions.
 */
void bfd_sessions_remove_manual(void)
{
	hash_iterate(bfd_key_hash, _bfd_session_remove_manual, NULL);
}

void bfd_profiles_remove(void)
{
	struct bfd_profile *bp;

	while ((bp = TAILQ_FIRST(&bplist)) != NULL)
		bfd_profile_free(bp);
}

struct __bfd_session_echo {
	/* VRF peers must match */
	struct vrf *vrf;
	/* Echo enabled or not */
	bool enabled;
};

static int __bfd_session_has_echo(struct hash_bucket *hb, void *arg)
{
	const struct bfd_session *session = hb->data;
	struct __bfd_session_echo *has_echo = arg;

	if (session->vrf != has_echo->vrf)
		return HASHWALK_CONTINUE;
	if (!CHECK_FLAG(session->flags, BFD_SESS_FLAG_ECHO))
		return HASHWALK_CONTINUE;

	has_echo->enabled = true;
	return HASHWALK_ABORT;
}

void bfd_vrf_toggle_echo(struct bfd_vrf_global *bfd_vrf)
{
	struct __bfd_session_echo has_echo = {
		.enabled = false,
		.vrf = bfd_vrf->vrf,
	};

	/* Check for peers using echo */
	hash_walk(bfd_id_hash, __bfd_session_has_echo, &has_echo);

	/*
	 * No peers using echo, close all echo sockets.
	 */
	if (!has_echo.enabled) {
		if (bfd_vrf->bg_echo != -1) {
			event_cancel(&bfd_vrf->bg_ev[4]);
			close(bfd_vrf->bg_echo);
			bfd_vrf->bg_echo = -1;
		}

		if (bfd_vrf->bg_echov6 != -1) {
			event_cancel(&bfd_vrf->bg_ev[5]);
			close(bfd_vrf->bg_echov6);
			bfd_vrf->bg_echov6 = -1;
		}
		return;
	}

	/*
	 * At least one peer using echo, open echo sockets.
	 */
	if (bfd_vrf->bg_echo == -1)
		bfd_vrf->bg_echo = bp_echo_socket(bfd_vrf->vrf);
	if (bfd_vrf->bg_echov6 == -1)
		bfd_vrf->bg_echov6 = bp_echov6_socket(bfd_vrf->vrf);

	if (bfd_vrf->bg_ev[4] == NULL && bfd_vrf->bg_echo != -1)
		event_add_read(master, bfd_recv_cb, bfd_vrf, bfd_vrf->bg_echo, &bfd_vrf->bg_ev[4]);
	if (bfd_vrf->bg_ev[5] == NULL && bfd_vrf->bg_echov6 != -1)
		event_add_read(master, bfd_recv_cb, bfd_vrf, bfd_vrf->bg_echov6, &bfd_vrf->bg_ev[5]);
}

/*
 * Profile related hash functions.
 */
static void _bfd_profile_update(struct hash_bucket *hb, void *arg)
{
	struct bfd_profile *bp = arg;
	struct bfd_session *bs = hb->data;

	/* This session is not using the profile. */
	if (bs->profile_name == NULL || strcmp(bs->profile_name, bp->name) != 0)
		return;

	bfd_profile_apply(bp->name, bs);
}

void bfd_profile_update(struct bfd_profile *bp)
{
	hash_iterate(bfd_key_hash, _bfd_profile_update, bp);
}

static void _bfd_profile_detach(struct hash_bucket *hb, void *arg)
{
	struct bfd_profile *bp = arg;
	struct bfd_session *bs = hb->data;

	/* This session is not using the profile. */
	if (bs->profile_name == NULL || strcmp(bs->profile_name, bp->name) != 0)
		return;

	bfd_profile_remove(bs);
}

static void bfd_profile_detach(struct bfd_profile *bp)
{
	hash_iterate(bfd_key_hash, _bfd_profile_detach, bp);
}

/*
 * Permitted VRFs related functions.
 */

static bool bfd_vrf_is_perm(const char *vrf_name)
{
	if (!bfd_perm_vrfs_count(&bfd_perm_vrfs))
		return true;

	return _bfd_perm_vrf_find(vrf_name) ? true : false;
}

static void insert_bfd_perm_vrf(const char *vrf_name)
{
	struct bfd_perm_vrf *vrf_item;

	vrf_item = _bfd_perm_vrf_find(vrf_name);

	if (vrf_item)
		return;

	vrf_item = XCALLOC(MTYPE_BFD_PERM_VRF, sizeof(*vrf_item));
	vrf_item->vrf_name = XSTRDUP(MTYPE_TMP, vrf_name);

	bfd_perm_vrfs_add(&bfd_perm_vrfs, vrf_item);
}

static void init_bfd_perm_vrfs_data(const char *context)
{
	bfd_perm_vrfs_init(&bfd_perm_vrfs);

	if (!context || *context == '\0')
		return;

	const char *delim = ",";
	char **vrfs_list;
	int num;

	frrstr_split(context, delim, &vrfs_list, &num);

	for (int i = 0; i < num; i++)
		insert_bfd_perm_vrf(vrfs_list[i]);

	XFREE(MTYPE_TMP, vrfs_list);
}

static void destroy_bfd_perm_vrfs_data(void)
{
	struct bfd_perm_vrf *vrf_item;

	frr_each_safe (bfd_perm_vrfs, &bfd_perm_vrfs, vrf_item) {
		XFREE(MTYPE_TMP, vrf_item->vrf_name);
		XFREE(MTYPE_BFD_PERM_VRF, vrf_item);
	}
}

/*
 * VRF related functions.
 */
static int bfd_vrf_new(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf;

	if (bglobal.debug_zebra)
		zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	bvrf = XCALLOC(MTYPE_BFDD_VRF, sizeof(struct bfd_vrf_global));
	bvrf->vrf = vrf;
	vrf->info = bvrf;

	/* Invalidate all sockets */
	bvrf->bg_shop = -1;
	bvrf->bg_mhop = -1;
	bvrf->bg_shop6 = -1;
	bvrf->bg_mhop6 = -1;
	bvrf->bg_echo = -1;
	bvrf->bg_echov6 = -1;
	bvrf->bg_initv6 = -1;

	return 0;
}

static int bfd_vrf_delete(struct vrf *vrf)
{
	if (bglobal.debug_zebra)
		zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	XFREE(MTYPE_BFDD_VRF, vrf->info);

	return 0;
}

static int bfd_vrf_enable(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf = vrf->info;

	if (bglobal.debug_zebra)
		zlog_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);

	/* Don't open sockets when using data plane */
	if (bglobal.bg_use_dplane)
		goto skip_sockets;

	if (!bfd_vrf_is_perm(vrf->name))
		return 0;

	if (bvrf->bg_shop == -1)
		bvrf->bg_shop = bp_udp_shop(vrf);
	if (bvrf->bg_mhop == -1)
		bvrf->bg_mhop = bp_udp_mhop(vrf);
	if (bvrf->bg_shop6 == -1)
		bvrf->bg_shop6 = bp_udp6_shop(vrf);
	if (bvrf->bg_mhop6 == -1)
		bvrf->bg_mhop6 = bp_udp6_mhop(vrf);
	if (bvrf->bg_initv6 == -1)
		bvrf->bg_initv6 = bp_initv6_socket(vrf);

	if (bvrf->bg_ev[0] == NULL && bvrf->bg_shop != -1)
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_shop,
			       &bvrf->bg_ev[0]);
	if (bvrf->bg_ev[1] == NULL && bvrf->bg_mhop != -1)
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_mhop,
			       &bvrf->bg_ev[1]);
	if (bvrf->bg_ev[2] == NULL && bvrf->bg_shop6 != -1)
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_shop6,
			       &bvrf->bg_ev[2]);
	if (bvrf->bg_ev[3] == NULL && bvrf->bg_mhop6 != -1)
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_mhop6,
			       &bvrf->bg_ev[3]);
	if (bvrf->bg_ev[6] == NULL && bvrf->bg_initv6 != -1)
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_initv6, &bvrf->bg_ev[6]);

	/* Toggle echo if VRF was disabled. */
	bfd_vrf_toggle_echo(bvrf);

skip_sockets:
	if (vrf->vrf_id != VRF_DEFAULT) {
		bfdd_zclient_register(vrf->vrf_id);
		bfdd_sessions_enable_vrf(vrf);
	}

	return 0;
}

static int bfd_vrf_disable(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf;

	if (!vrf->info)
		return 0;
	bvrf = vrf->info;

	if (vrf->vrf_id != VRF_DEFAULT) {
		bfdd_sessions_disable_vrf(vrf);
		bfdd_zclient_unregister(vrf->vrf_id);
	}

	if (bglobal.debug_zebra)
		zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	/* Disable read/write poll triggering. */
	event_cancel(&bvrf->bg_ev[0]);
	event_cancel(&bvrf->bg_ev[1]);
	event_cancel(&bvrf->bg_ev[2]);
	event_cancel(&bvrf->bg_ev[3]);
	event_cancel(&bvrf->bg_ev[4]);
	event_cancel(&bvrf->bg_ev[5]);
	event_cancel(&bvrf->bg_ev[6]);

	/* Close all descriptors. */
	socket_close(&bvrf->bg_echo);
	socket_close(&bvrf->bg_shop);
	socket_close(&bvrf->bg_mhop);
	socket_close(&bvrf->bg_shop6);
	socket_close(&bvrf->bg_mhop6);
	socket_close(&bvrf->bg_echov6);
	socket_close(&bvrf->bg_initv6);

	return 0;
}

void bfd_vrf_init(const char *context)
{
	init_bfd_perm_vrfs_data(context);
	vrf_init(bfd_vrf_new, bfd_vrf_enable, bfd_vrf_disable, bfd_vrf_delete);
}

void bfd_vrf_terminate(void)
{
	vrf_terminate();
}

struct bfd_vrf_global *bfd_vrf_look_by_session(struct bfd_session *bfd)
{
	struct vrf *vrf;

	if (!vrf_is_backend_netns()) {
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
		if (vrf)
			return (struct bfd_vrf_global *)vrf->info;
		return NULL;
	}
	if (!bfd)
		return NULL;
	if (!bfd->vrf)
		return NULL;
	return bfd->vrf->info;
}

unsigned long bfd_get_session_count(void)
{
	return bfd_key_hash->count;
}

struct sbfd_reflector *sbfd_reflector_new(const uint32_t discr, struct in6_addr *sip)
{
	struct sbfd_reflector *sr;

	sr = sbfd_discr_lookup(discr);
	if (sr)
		return sr;

	sr = XCALLOC(MTYPE_SBFD_REFLECTOR, sizeof(*sr));
	sr->discr = discr;
	memcpy(&sr->local, sip, sizeof(struct in6_addr));

	sbfd_discr_insert(sr);


	return sr;
}

void sbfd_reflector_free(const uint32_t discr)
{
	struct sbfd_reflector *sr;

	sr = sbfd_discr_lookup(discr);
	if (!sr)
		return;

	sbfd_discr_delete(discr);
	XFREE(MTYPE_SBFD_REFLECTOR, sr);

	return;
}

void sbfd_reflector_flush(void)
{
	sbfd_discr_iterate(_sbfd_reflector_free, NULL);
	return;
}

struct bfd_session_name_match_unique {
	const char *bfd_name;
	struct bfd_session *bfd_found;
};

static int _bfd_session_name_cmp(struct hash_bucket *hb, void *arg)
{
	struct bfd_session *bs = hb->data;
	struct bfd_session_name_match_unique *match = (struct bfd_session_name_match_unique *)arg;

	if (strlen(bs->bfd_name) != strlen(match->bfd_name)) {
		return HASHWALK_CONTINUE;
	}

	if (!strncmp(bs->bfd_name, match->bfd_name, strlen(bs->bfd_name))) {
		match->bfd_found = bs;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct bfd_session *bfd_session_get_by_name(const char *name)
{
	if (!name || name[0] == '\0')
		return NULL;

	struct bfd_session_name_match_unique match;
	match.bfd_name = name;
	match.bfd_found = NULL;

	hash_walk(bfd_key_hash, _bfd_session_name_cmp, &match);

	return match.bfd_found;
}

void bfd_rtt_init(struct bfd_session *bfd)
{
	uint8_t i;

	/* initialize RTT */
	bfd->rtt_valid = 0;
	bfd->rtt_index = 0;
	for (i = 0; i < BFD_RTT_SAMPLE; i++)
		bfd->rtt[i] = 0;
}
