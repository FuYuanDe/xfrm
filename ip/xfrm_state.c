/* $USAGI: $ */

/*
 * Copyright (C)2004 USAGI/WIDE Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
/*
 * based on iproute.c
 */
/*
 * Authors:
 *	Masahide NAKAMURA @USAGI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include "utils.h"
#include "xfrm.h"
#include "ip_common.h"

/* #define NLMSG_DELETEALL_BUF_SIZE (4096-512) */
#define NLMSG_DELETEALL_BUF_SIZE 8192

/*
 * Receiving buffer defines:
 * nlmsg
 *   data = struct xfrm_usersa_info
 *   rtattr
 *   rtattr
 *   ... (max count of rtattr is XFRM_MAX+1
 *
 *  each rtattr data = struct xfrm_algo(dynamic size) or xfrm_address_t
 */
#define NLMSG_BUF_SIZE 4096
#define RTA_BUF_SIZE 2048
#define XFRM_ALGO_KEY_BUF_SIZE 512
#define CTX_BUF_SIZE 256

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: ip xfrm state { add | update } ID [ ALGO-LIST ] [ mode MODE ]\n");
	fprintf(stderr, "        [ mark MARK [ mask MASK ] ] [ reqid REQID ] [ seq SEQ ]\n");
	fprintf(stderr, "        [ replay-window SIZE ] [ replay-seq SEQ ] [ replay-oseq SEQ ]\n");
	fprintf(stderr, "        [ replay-seq-hi SEQ ] [ replay-oseq-hi SEQ ]\n");
	fprintf(stderr, "        [ flag FLAG-LIST ] [ sel SELECTOR ] [ LIMIT-LIST ] [ encap ENCAP ]\n");
	fprintf(stderr, "        [ coa ADDR[/PLEN] ] [ ctx CTX ] [ extra-flag EXTRA-FLAG-LIST ]\n");
	fprintf(stderr, "Usage: ip xfrm state allocspi ID [ mode MODE ] [ mark MARK [ mask MASK ] ]\n");
	fprintf(stderr, "        [ reqid REQID ] [ seq SEQ ] [ min SPI max SPI ]\n");
	fprintf(stderr, "Usage: ip xfrm state { delete | get } ID [ mark MARK [ mask MASK ] ]\n");
	fprintf(stderr, "Usage: ip xfrm state { deleteall | list } [ ID ] [ mode MODE ] [ reqid REQID ]\n");
	fprintf(stderr, "        [ flag FLAG-LIST ]\n");
	fprintf(stderr, "Usage: ip xfrm state flush [ proto XFRM-PROTO ]\n");
	fprintf(stderr, "Usage: ip xfrm state count\n");
	fprintf(stderr, "ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]\n");
	fprintf(stderr, "XFRM-PROTO := ");
	fprintf(stderr, "%s | ", strxf_xfrmproto(IPPROTO_ESP));
	fprintf(stderr, "%s | ", strxf_xfrmproto(IPPROTO_AH));
	fprintf(stderr, "%s | ", strxf_xfrmproto(IPPROTO_COMP));
	fprintf(stderr, "%s | ", strxf_xfrmproto(IPPROTO_ROUTING));
	fprintf(stderr, "%s\n", strxf_xfrmproto(IPPROTO_DSTOPTS));
	fprintf(stderr, "ALGO-LIST := [ ALGO-LIST ] ALGO\n");
	fprintf(stderr, "ALGO := { ");
	fprintf(stderr, "%s | ", strxf_algotype(XFRMA_ALG_CRYPT));
	fprintf(stderr, "%s", strxf_algotype(XFRMA_ALG_AUTH));
	fprintf(stderr, " } ALGO-NAME ALGO-KEYMAT |\n");
	fprintf(stderr, "        %s", strxf_algotype(XFRMA_ALG_AUTH_TRUNC));
	fprintf(stderr, " ALGO-NAME ALGO-KEYMAT ALGO-TRUNC-LEN |\n");
	fprintf(stderr, "        %s", strxf_algotype(XFRMA_ALG_AEAD));
	fprintf(stderr, " ALGO-NAME ALGO-KEYMAT ALGO-ICV-LEN |\n");
	fprintf(stderr, "        %s", strxf_algotype(XFRMA_ALG_COMP));
	fprintf(stderr, " ALGO-NAME\n");
	fprintf(stderr, "MODE := transport | tunnel | beet | ro | in_trigger\n");
	fprintf(stderr, "FLAG-LIST := [ FLAG-LIST ] FLAG\n");
	fprintf(stderr, "FLAG := noecn | decap-dscp | nopmtudisc | wildrecv | icmp | af-unspec | align4 | esn\n");
	fprintf(stderr, "EXTRA-FLAG-LIST := [ EXTRA-FLAG-LIST ] EXTRA-FLAG\n");
	fprintf(stderr, "EXTRA-FLAG := dont-encap-dscp\n");
	fprintf(stderr, "SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]\n");
	fprintf(stderr, "UPSPEC := proto { { ");
	fprintf(stderr, "%s | ", strxf_proto(IPPROTO_TCP));
	fprintf(stderr, "%s | ", strxf_proto(IPPROTO_UDP));
	fprintf(stderr, "%s | ", strxf_proto(IPPROTO_SCTP));
	fprintf(stderr, "%s", strxf_proto(IPPROTO_DCCP));
	fprintf(stderr, " } [ sport PORT ] [ dport PORT ] |\n");
	fprintf(stderr, "                  { ");
	fprintf(stderr, "%s | ", strxf_proto(IPPROTO_ICMP));
	fprintf(stderr, "%s | ", strxf_proto(IPPROTO_ICMPV6));
	fprintf(stderr, "%s", strxf_proto(IPPROTO_MH));
	fprintf(stderr, " } [ type NUMBER ] [ code NUMBER ] |\n");
	fprintf(stderr, "                  %s", strxf_proto(IPPROTO_GRE));
	fprintf(stderr, " [ key { DOTTED-QUAD | NUMBER } ] | PROTO }\n");
	fprintf(stderr, "LIMIT-LIST := [ LIMIT-LIST ] limit LIMIT\n");
	fprintf(stderr, "LIMIT := { time-soft | time-hard | time-use-soft | time-use-hard } SECONDS |\n");
	fprintf(stderr, "         { byte-soft | byte-hard } SIZE | { packet-soft | packet-hard } COUNT\n");
	fprintf(stderr, "ENCAP := { espinudp | espinudp-nonike } SPORT DPORT OADDR\n");

	exit(-1);
}

static int xfrm_algo_parse(struct xfrm_algo *alg, enum xfrm_attr_type_t type,
			   char *name, char *key, char *buf, int max)
{
	int len;
	int slen = strlen(key);

#if 0
	/* XXX: verifying both name and key is required! */
	fprintf(stderr, "warning: ALGO-NAME/ALGO-KEYMAT values will be sent to the kernel promiscuously! (verifying them isn't implemented yet)\n");
#endif

	strncpy(alg->alg_name, name, sizeof(alg->alg_name));

	if (slen > 2 && strncmp(key, "0x", 2) == 0) {
		/* split two chars "0x" from the top */
		char *p = key + 2;
		int plen = slen - 2;
		int i;
		int j;

		/* Converting hexadecimal numbered string into real key;
		 * Convert each two chars into one char(value). If number
		 * of the length is odd, add zero on the top for rounding.
		 */

		/* calculate length of the converted values(real key) */
		len = (plen + 1) / 2;
		if (len > max)
			invarg("ALGO-KEYMAT value makes buffer overflow\n", key);

		for (i = -(plen % 2), j = 0; j < len; i += 2, j++) {
			char vbuf[3];
			__u8 val;

			vbuf[0] = i >= 0 ? p[i] : '0';
			vbuf[1] = p[i + 1];
			vbuf[2] = '\0';

			if (get_u8(&val, vbuf, 16))
				invarg("ALGO-KEYMAT value is invalid", key);

			buf[j] = val;
		}
	} else {
		len = slen;
		if (len > 0) {
			if (len > max)
				invarg("ALGO-KEYMAT value makes buffer overflow\n", key);

			memcpy(buf, key, len);
		}
	}

	alg->alg_key_len = len * 8;

	return 0;
}

static int xfrm_seq_parse(__u32 *seq, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;

	if (get_be32(seq, *argv, 0))
		invarg("SEQ value is invalid", *argv);

	*argcp = argc;
	*argvp = argv;

	return 0;
}
/// xfrm_state_flag_parse(&req.xsinfo.flags, &argc, &argv);
static int xfrm_state_flag_parse(__u8 *flags, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;
	int len = strlen(*argv);

	if (len > 2 && strncmp(*argv, "0x", 2) == 0) {
		__u8 val = 0;

		if (get_u8(&val, *argv, 16))
			invarg("FLAG value is invalid", *argv);
		*flags = val;
	} else {
		while (1) {
			if (strcmp(*argv, "noecn") == 0)
				*flags |= XFRM_STATE_NOECN;
			else if (strcmp(*argv, "decap-dscp") == 0)
				*flags |= XFRM_STATE_DECAP_DSCP;
			else if (strcmp(*argv, "nopmtudisc") == 0)
				*flags |= XFRM_STATE_NOPMTUDISC;
			else if (strcmp(*argv, "wildrecv") == 0)
				*flags |= XFRM_STATE_WILDRECV;
			else if (strcmp(*argv, "icmp") == 0)
				*flags |= XFRM_STATE_ICMP;
			else if (strcmp(*argv, "af-unspec") == 0)
				*flags |= XFRM_STATE_AF_UNSPEC;
			else if (strcmp(*argv, "align4") == 0)
				*flags |= XFRM_STATE_ALIGN4;
			else if (strcmp(*argv, "esn") == 0)
				*flags |= XFRM_STATE_ESN;
			else {
				PREV_ARG(); /* back track */
				break;
			}

			if (!NEXT_ARG_OK())
				break;
			NEXT_ARG();
		}
	}

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int xfrm_state_extra_flag_parse(__u32 *extra_flags, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;
	int len = strlen(*argv);

	if (len > 2 && strncmp(*argv, "0x", 2) == 0) {
		__u32 val = 0;

		if (get_u32(&val, *argv, 16))
			invarg("\"EXTRA-FLAG\" is invalid", *argv);
		*extra_flags = val;
	} else {
		while (1) {
			if (strcmp(*argv, "dont-encap-dscp") == 0)
				*extra_flags |= XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
			else {
				PREV_ARG(); /* back track */
				break;
			}

			if (!NEXT_ARG_OK())
				break;
			NEXT_ARG();
		}
	}

	*argcp = argc;
	*argvp = argv;

	return 0;
}

/// xfrm_state_modify(XFRM_MSG_NEWSA, 0, argc-1, argv+1);
/// 这里第一个参数cmd是不是应该定义为 nlmsg_type

/// 添加SA处理函数，新添的nlmsg_type类型是 XFRM_MSG_NEWSA
/// 与之类似的消息类型是 XFRM_MSG_NEWSADINFO
/// 这个貌似与数据库数据相关
static int xfrm_state_modify(int cmd, unsigned int flags, int argc, char **argv)
{
/// 这里第一个参数cmd就是消息类型
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr	n;
		struct xfrm_usersa_info xsinfo;
		char			buf[RTA_BUF_SIZE];
	} req = {
///这里netlink消息长度包含一个xfrm_usersa_info结构。
///这个结构体应该就是SA的实体，用于传递给内核部分。
///xfrm_usersa_info定义在linux/xfrm.h文件中。
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsinfo)),
/// NLM_F_REQUEST 定义在netlink.h中，
/// 这个标志位属于什么消息呢
/// 按位或运算
		.n.nlmsg_flags = NLM_F_REQUEST | flags,

/// 这里消息类型为 XFRM_MSG_NEWSA
		.n.nlmsg_type = cmd,
		
/// 默认情况下 preferred_family宏定义值为 AF_UNSPEC，即未定义 		
		.xsinfo.family = preferred_family,
/// 该值定义在 linux/xfrm.h中
/// #define XFRM_INF (~(__u64)0)
/// RFC 应该多去阅读
/// 这些值用于默认值
		.xsinfo.lft.soft_byte_limit = XFRM_INF,
		.xsinfo.lft.hard_byte_limit = XFRM_INF,
		.xsinfo.lft.soft_packet_limit = XFRM_INF,
		.xsinfo.lft.hard_packet_limit = XFRM_INF,
	};

/// 接下来这一堆参数怎么用的
/// 内含三个参数oseq,seq,bitmap
	struct xfrm_replay_state replay = {};

/// 需要记住所配置的参数
/// bmp_len,oseq,seq,oseq_hi,seq_hi,replay_window,bmp
	struct xfrm_replay_state_esn replay_esn = {};
	__u32 replay_window = 0;
	__u32 seq = 0, oseq = 0, seq_hi = 0, oseq_hi = 0;

/// 哈，又见到了这个指针
	char *idp = NULL;

/// 加密认证
	char *aeadop = NULL;
/// 加密
	char *ealgop = NULL;
/// 认证
	char *aalgop = NULL;
/// 压缩，	
	char *calgop = NULL;
	char *coap = NULL;
	char *sctxp = NULL;
/// 
	__u32 extra_flags = 0;

/// 该结构包含值和掩码两个部分	
/// 这个结构在什么情况下会用到
	struct xfrm_mark mark = {0, 0};
	struct {
		struct xfrm_user_sec_ctx sctx;
		char    str[CTX_BUF_SIZE];
	} ctx = {};

/// 循环分析参数
	while (argc > 0) {
/// 处理参数队列中第一个参数
		if (strcmp(*argv, "mode") == 0) {
/// argv++		
			NEXT_ARG();
/// 传递的参数包含一个三维指针	
/// 传递相同的参数给被调函数应该这样做
/// xfrm_mode_parse 用于设置xsinfo结构mode模式
			xfrm_mode_parse(&req.xsinfo.mode, &argc, &argv);
		} else if (strcmp(*argv, "mark") == 0) {
/// xfrm_parse_mark 用于设置 mark 掩码，函数短小精湛，值得学习		
			xfrm_parse_mark(&mark, &argc, &argv);
		} else if (strcmp(*argv, "reqid") == 0) {
			NEXT_ARG();
/// 这个参数 reqid 是干嘛的			
/// 调用get_u32函数提取数值。
/// 用于设置 xsinfo 结构reqid,该结构包含新的SA信息。
/// 对于reqid和seq等目前不清楚含义的属性，先跳过，之后再来看
			xfrm_reqid_parse(&req.xsinfo.reqid, &argc, &argv);
		} else if (strcmp(*argv, "seq") == 0) {
			NEXT_ARG();
/// 调用get_u32函数提取数值。
/// 用于设置 xsinfo 结构seq,该结构包含新的SA信息。			
			xfrm_seq_parse(&req.xsinfo.seq, &argc, &argv);
		} else if (strcmp(*argv, "replay-window") == 0) {
			NEXT_ARG();
/// 调用get_u32函数提取数值。
/// 用于设置 replay_window结构体
/// 该结构体是干嘛的 replay_window
			if (get_u32(&replay_window, *argv, 0))
				invarg("value after \"replay-window\" is invalid", *argv);
		} else if (strcmp(*argv, "replay-seq") == 0) {

/// 调用get_u32函数提取数值。
/// 用于设置 replay-seq结构体
/// 该结构体是干嘛的replay-seq
			NEXT_ARG();
/// 设置seq			
			if (get_u32(&seq, *argv, 0))
				invarg("value after \"replay-seq\" is invalid", *argv);
		} else if (strcmp(*argv, "replay-seq-hi") == 0) {
			NEXT_ARG();
/// 设置seq_hi			
			if (get_u32(&seq_hi, *argv, 0))
				invarg("value after \"replay-seq-hi\" is invalid", *argv);
		} else if (strcmp(*argv, "replay-oseq") == 0) {

			NEXT_ARG();
			if (get_u32(&oseq, *argv, 0))
/// 设置oseq			
				invarg("value after \"replay-oseq\" is invalid", *argv);
		} else if (strcmp(*argv, "replay-oseq-hi") == 0) {
			NEXT_ARG();
/// 设置oseq_hi			
			if (get_u32(&oseq_hi, *argv, 0))
				invarg("value after \"replay-oseq-hi\" is invalid", *argv);
		} else if (strcmp(*argv, "flag") == 0) {
			NEXT_ARG();
/// 这个flags是用来做什么的			
			xfrm_state_flag_parse(&req.xsinfo.flags, &argc, &argv);
		} else if (strcmp(*argv, "extra-flag") == 0) {
			NEXT_ARG();
/// 这个extra_flags又是用来做什么的			
			xfrm_state_extra_flag_parse(&extra_flags, &argc, &argv);
		} else if (strcmp(*argv, "sel") == 0) {
			NEXT_ARG();
			preferred_family = AF_UNSPEC;
			xfrm_selector_parse(&req.xsinfo.sel, &argc, &argv);
			preferred_family = req.xsinfo.sel.family;
		} else if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			xfrm_lifetime_cfg_parse(&req.xsinfo.lft, &argc, &argv);
		} 
		else if (strcmp(*argv, "encap") == 0) {
			struct xfrm_encap_tmpl encap;
			inet_prefix oa;
			NEXT_ARG();
			xfrm_encap_type_parse(&encap.encap_type, &argc, &argv);
			NEXT_ARG();
			if (get_be16(&encap.encap_sport, *argv, 0))
				invarg("SPORT value after \"encap\" is invalid", *argv);
			NEXT_ARG();
			if (get_be16(&encap.encap_dport, *argv, 0))
				invarg("DPORT value after \"encap\" is invalid", *argv);
			NEXT_ARG();
			get_addr(&oa, *argv, AF_UNSPEC);
			memcpy(&encap.encap_oa, &oa.data, sizeof(encap.encap_oa));
/// 如果存在encap属性的话，则在消息属性里添加该信息
/// 如果是其它属性的话，只是赋值而encap属性是直接封装属性信息
			addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
				  (void *)&encap, sizeof(encap));
		} 
		else if (strcmp(*argv, "coa") == 0) {
			inet_prefix coa;
			xfrm_address_t xcoa = {};

			if (coap)
				duparg("coa", *argv);
			coap = *argv;

			NEXT_ARG();

			get_prefix(&coa, *argv, preferred_family);
			if (coa.family == AF_UNSPEC)
				invarg("value after \"coa\" has an unrecognized address family", *argv);
			if (coa.bytelen > sizeof(xcoa))
				invarg("value after \"coa\" is too large", *argv);

			memcpy(&xcoa, &coa.data, coa.bytelen);
/// 添加属性类型为XFRMA_COADDR的属性
			addattr_l(&req.n, sizeof(req.buf), XFRMA_COADDR,
				  (void *)&xcoa, sizeof(xcoa));
		} 
		else if (strcmp(*argv, "ctx") == 0) {
			char *context;

			if (sctxp)
				duparg("ctx", *argv);
			sctxp = *argv;

			NEXT_ARG();
			context = *argv;

			xfrm_sctx_parse((char *)&ctx.str, context, &ctx.sctx);
/// 添加属性类型为XFRMA_SEC_CTX的属性
			addattr_l(&req.n, sizeof(req.buf), XFRMA_SEC_CTX,
				  (void *)&ctx, ctx.sctx.len);
		} 
		else {
			/* try to assume ALGO */
			int type = xfrm_algotype_getbyname(*argv);
/// 这些XFRMA_XXX属性定义咋linux/xfrm.h头文件中
			switch (type) {
			case XFRMA_ALG_AEAD:
			case XFRMA_ALG_CRYPT:
			case XFRMA_ALG_AUTH:
			case XFRMA_ALG_AUTH_TRUNC:
			case XFRMA_ALG_COMP:
			{
				/* ALGO */
				struct {
					union {
						struct xfrm_algo alg;
						struct xfrm_algo_aead aead;
						struct xfrm_algo_auth auth;
					} u;
					char buf[XFRM_ALGO_KEY_BUF_SIZE];
				} alg = {};
				int len;
				__u32 icvlen, trunclen;
				char *name;
/// 这是怎样的定义方式				
				char *key = "";
				char *buf;

				switch (type) {
				case XFRMA_ALG_AEAD:
					if (ealgop || aalgop || aeadop)
						duparg("ALGO-TYPE", *argv);
					aeadop = *argv;
					break;
				case XFRMA_ALG_CRYPT:
					if (ealgop || aeadop)
						duparg("ALGO-TYPE", *argv);
					ealgop = *argv;
					break;
				case XFRMA_ALG_AUTH:
				case XFRMA_ALG_AUTH_TRUNC:
					if (aalgop || aeadop)
						duparg("ALGO-TYPE", *argv);
					aalgop = *argv;
					break;
				case XFRMA_ALG_COMP:
					if (calgop)
						duparg("ALGO-TYPE", *argv);
					calgop = *argv;
					break;
				default:
					/* not reached */
					invarg("ALGO-TYPE value is invalid\n", *argv);
				}

				if (!NEXT_ARG_OK())
					missarg("ALGO-NAME");
				NEXT_ARG();
				name = *argv;

				switch (type) {
				case XFRMA_ALG_AEAD:
				case XFRMA_ALG_CRYPT:
				case XFRMA_ALG_AUTH:
				case XFRMA_ALG_AUTH_TRUNC:
					if (!NEXT_ARG_OK())
						missarg("ALGO-KEYMAT");
					NEXT_ARG();
					key = *argv;
					break;
				}

				buf = alg.u.alg.alg_key;
				len = sizeof(alg.u.alg);

				switch (type) {
				case XFRMA_ALG_AEAD:
					if (!NEXT_ARG_OK())
						missarg("ALGO-ICV-LEN");
					NEXT_ARG();
					if (get_u32(&icvlen, *argv, 0))
						invarg("ALGO-ICV-LEN value is invalid",
						       *argv);
					alg.u.aead.alg_icv_len = icvlen;

					buf = alg.u.aead.alg_key;
					len = sizeof(alg.u.aead);
					break;
				case XFRMA_ALG_AUTH_TRUNC:
					if (!NEXT_ARG_OK())
						missarg("ALGO-TRUNC-LEN");
					NEXT_ARG();
					if (get_u32(&trunclen, *argv, 0))
						invarg("ALGO-TRUNC-LEN value is invalid",
						       *argv);
					alg.u.auth.alg_trunc_len = trunclen;

					buf = alg.u.auth.alg_key;
					len = sizeof(alg.u.auth);
					break;
				}

				xfrm_algo_parse((void *)&alg, type, name, key,
						buf, sizeof(alg.buf));
				len += alg.u.alg.alg_key_len;

				addattr_l(&req.n, sizeof(req.buf), type,
					  (void *)&alg, len);
				break;
			}
			default:
				/* try to assume ID */
				if (idp)
					invarg("unknown", *argv);
/// 这里idp被处理 
				idp = *argv;

				/* ID */
				xfrm_id_parse(&req.xsinfo.saddr, &req.xsinfo.id,
					      &req.xsinfo.family, 0, &argc, &argv);
				if (preferred_family == AF_UNSPEC)
					preferred_family = req.xsinfo.family;
			}
		}
		argc--; argv++;
	}

	if (req.xsinfo.flags & XFRM_STATE_ESN &&
	    replay_window == 0) {
		fprintf(stderr, "Error: esn flag set without replay-window.\n");
		exit(-1);
	}

	if (replay_window > XFRMA_REPLAY_ESN_MAX) {
		fprintf(stderr,
			"Error: replay-window (%u) > XFRMA_REPLAY_ESN_MAX (%u).\n",
			replay_window, XFRMA_REPLAY_ESN_MAX);
		exit(-1);
	}


/// 接下来设置nlmsghdr
/// 这些标志位flags是什么意思呢

	if (req.xsinfo.flags & XFRM_STATE_ESN ||
	    replay_window > (sizeof(replay.bitmap) * 8)) {
		replay_esn.seq = seq;
		replay_esn.oseq = oseq;
		replay_esn.seq_hi = seq_hi;
		replay_esn.oseq_hi = oseq_hi;
		replay_esn.replay_window = replay_window;
		replay_esn.bmp_len = (replay_window + sizeof(__u32) * 8 - 1) /
				     (sizeof(__u32) * 8);
		addattr_l(&req.n, sizeof(req.buf), XFRMA_REPLAY_ESN_VAL,
			  &replay_esn, sizeof(replay_esn));
	} else {
		if (seq || oseq) {
			replay.seq = seq;
			replay.oseq = oseq;
			addattr_l(&req.n, sizeof(req.buf), XFRMA_REPLAY_VAL,
				  &replay, sizeof(replay));
		}
/// 初始化replay_window		
		req.xsinfo.replay_window = replay_window;
	}

	if (extra_flags)
		addattr32(&req.n, sizeof(req.buf), XFRMA_SA_EXTRA_FLAGS,
			  extra_flags);
/// 这个在上面哪里一定处理了
	if (!idp) {
		fprintf(stderr, "Not enough information: ID is required\n");
		exit(1);
	}
/// 可以看到，mark在这里被单独处理
/// 所谓处理就是单独一条attribute
	if (mark.m) {
		int r = addattr_l(&req.n, sizeof(req.buf), XFRMA_MARK,
				  (void *)&mark, sizeof(mark));
		if (r < 0) {
			fprintf(stderr, "XFRMA_MARK failed\n");
			exit(1);
		}
	}

	if (xfrm_xfrmproto_is_ipsec(req.xsinfo.id.proto)) {
		switch (req.xsinfo.mode) {
		case XFRM_MODE_TRANSPORT:
		case XFRM_MODE_TUNNEL:
			break;
		case XFRM_MODE_BEET:
			if (req.xsinfo.id.proto == IPPROTO_ESP)
				break;
		default:
			fprintf(stderr, "MODE value is invalid with XFRM-PROTO value \"%s\"\n",
				strxf_xfrmproto(req.xsinfo.id.proto));
			exit(1);
		}

		switch (req.xsinfo.id.proto) {
		case IPPROTO_ESP:
			if (calgop) {
				fprintf(stderr, "ALGO-TYPE value \"%s\" is invalid with XFRM-PROTO value \"%s\"\n",
					strxf_algotype(XFRMA_ALG_COMP),
					strxf_xfrmproto(req.xsinfo.id.proto));
				exit(1);
			}
			if (!ealgop && !aeadop) {
				fprintf(stderr, "ALGO-TYPE value \"%s\" or \"%s\" is required with XFRM-PROTO value \"%s\"\n",
					strxf_algotype(XFRMA_ALG_CRYPT),
					strxf_algotype(XFRMA_ALG_AEAD),
					strxf_xfrmproto(req.xsinfo.id.proto));
				exit(1);
			}
			break;
		case IPPROTO_AH:
			if (ealgop || aeadop || calgop) {
				fprintf(stderr, "ALGO-TYPE values \"%s\", \"%s\", and \"%s\" are invalid with XFRM-PROTO value \"%s\"\n",
					strxf_algotype(XFRMA_ALG_CRYPT),
					strxf_algotype(XFRMA_ALG_AEAD),
					strxf_algotype(XFRMA_ALG_COMP),
					strxf_xfrmproto(req.xsinfo.id.proto));
				exit(1);
			}
			if (!aalgop) {
				fprintf(stderr, "ALGO-TYPE value \"%s\" or \"%s\" is required with XFRM-PROTO value \"%s\"\n",
					strxf_algotype(XFRMA_ALG_AUTH),
					strxf_algotype(XFRMA_ALG_AUTH_TRUNC),
					strxf_xfrmproto(req.xsinfo.id.proto));
				exit(1);
			}
			break;
		case IPPROTO_COMP:
			if (ealgop || aalgop || aeadop) {
				fprintf(stderr, "ALGO-TYPE values \"%s\", \"%s\", \"%s\", and \"%s\" are invalid with XFRM-PROTO value \"%s\"\n",
					strxf_algotype(XFRMA_ALG_CRYPT),
					strxf_algotype(XFRMA_ALG_AUTH),
					strxf_algotype(XFRMA_ALG_AUTH_TRUNC),
					strxf_algotype(XFRMA_ALG_AEAD),
					strxf_xfrmproto(req.xsinfo.id.proto));
				exit(1);
			}
			if (!calgop) {
				fprintf(stderr, "ALGO-TYPE value \"%s\" is required with XFRM-PROTO value \"%s\"\n",
					strxf_algotype(XFRMA_ALG_COMP),
					strxf_xfrmproto(req.xsinfo.id.proto));
				exit(1);
			}
			break;
		}
	} else {
		if (ealgop || aalgop || aeadop || calgop) {
			fprintf(stderr, "ALGO is invalid with XFRM-PROTO value \"%s\"\n",
				strxf_xfrmproto(req.xsinfo.id.proto));
			exit(1);
		}
	}

	if (xfrm_xfrmproto_is_ro(req.xsinfo.id.proto)) {
		switch (req.xsinfo.mode) {
		case XFRM_MODE_ROUTEOPTIMIZATION:
		case XFRM_MODE_IN_TRIGGER:
			break;
		case 0:
			fprintf(stderr, "\"mode\" is required with XFRM-PROTO value \"%s\"\n",
				strxf_xfrmproto(req.xsinfo.id.proto));
			exit(1);
		default:
			fprintf(stderr, "MODE value is invalid with XFRM-PROTO value \"%s\"\n",
				strxf_xfrmproto(req.xsinfo.id.proto));
			exit(1);
		}

		if (!coap) {
			fprintf(stderr, "\"coa\" is required with XFRM-PROTO value \"%s\"\n",
				strxf_xfrmproto(req.xsinfo.id.proto));
			exit(1);
		}
	} else {
		if (coap) {
			fprintf(stderr, "\"coa\" is invalid with XFRM-PROTO value \"%s\"\n",
				strxf_xfrmproto(req.xsinfo.id.proto));
			exit(1);
		}
	}
/// 参数处理完毕

/// 与内核xfrm模块通信前的准备，包括建立套接字等。
	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (req.xsinfo.family == AF_UNSPEC)
		req.xsinfo.family = AF_INET;

/// 准备工作处理完，接下来和内核通信。
	if (rtnl_talk(&rth, &req.n, NULL, 0) < 0)
		exit(2);

	rtnl_close(&rth);

	return 0;
}

static int xfrm_state_allocspi(int argc, char **argv)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr	n;
		struct xfrm_userspi_info xspi;
		char			buf[RTA_BUF_SIZE];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xspi)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = XFRM_MSG_ALLOCSPI,
		.xspi.info.family = preferred_family,
#if 0
		.xspi.lft.soft_byte_limit = XFRM_INF,
		.xspi.lft.hard_byte_limit = XFRM_INF,
		.xspi.lft.soft_packet_limit = XFRM_INF,
		.xspi.lft.hard_packet_limit = XFRM_INF,
#endif
	};
	char *idp = NULL;
	char *minp = NULL;
	char *maxp = NULL;
	struct xfrm_mark mark = {0, 0};
	char res_buf[NLMSG_BUF_SIZE] = {};
	struct nlmsghdr *res_n = (struct nlmsghdr *)res_buf;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			xfrm_mode_parse(&req.xspi.info.mode, &argc, &argv);
		} else if (strcmp(*argv, "mark") == 0) {
			xfrm_parse_mark(&mark, &argc, &argv);
		} else if (strcmp(*argv, "reqid") == 0) {
			NEXT_ARG();
			xfrm_reqid_parse(&req.xspi.info.reqid, &argc, &argv);
		} else if (strcmp(*argv, "seq") == 0) {
			NEXT_ARG();
			xfrm_seq_parse(&req.xspi.info.seq, &argc, &argv);
		} else if (strcmp(*argv, "min") == 0) {
			if (minp)
				duparg("min", *argv);
			minp = *argv;

			NEXT_ARG();

			if (get_u32(&req.xspi.min, *argv, 0))
				invarg("value after \"min\" is invalid", *argv);
		} else if (strcmp(*argv, "max") == 0) {
			if (maxp)
				duparg("max", *argv);
			maxp = *argv;

			NEXT_ARG();

			if (get_u32(&req.xspi.max, *argv, 0))
				invarg("value after \"max\" is invalid", *argv);
		} else {
			/* try to assume ID */
			if (idp)
				invarg("unknown", *argv);
			idp = *argv;

			/* ID */
			xfrm_id_parse(&req.xspi.info.saddr, &req.xspi.info.id,
				      &req.xspi.info.family, 0, &argc, &argv);
			if (req.xspi.info.id.spi) {
				fprintf(stderr, "\"spi\" is invalid\n");
				exit(1);
			}
			if (preferred_family == AF_UNSPEC)
				preferred_family = req.xspi.info.family;
		}
		argc--; argv++;
	}

	if (!idp) {
		fprintf(stderr, "Not enough information: ID is required\n");
		exit(1);
	}

	if (minp) {
		if (!maxp) {
			fprintf(stderr, "\"max\" is missing\n");
			exit(1);
		}
		if (req.xspi.min > req.xspi.max) {
			fprintf(stderr, "value after \"min\" is larger than value after \"max\"\n");
			exit(1);
		}
	} else {
		if (maxp) {
			fprintf(stderr, "\"min\" is missing\n");
			exit(1);
		}

		/* XXX: Default value defined in PF_KEY;
		 * See kernel's net/key/af_key.c(pfkey_getspi).
		 */
		req.xspi.min = 0x100;
		req.xspi.max = 0x0fffffff;

		/* XXX: IPCOMP spi is 16-bits;
		 * See kernel's net/xfrm/xfrm_user(verify_userspi_info).
		 */
		if (req.xspi.info.id.proto == IPPROTO_COMP)
			req.xspi.max = 0xffff;
	}

	if (mark.m & mark.v) {
		int r = addattr_l(&req.n, sizeof(req.buf), XFRMA_MARK,
				  (void *)&mark, sizeof(mark));
		if (r < 0) {
			fprintf(stderr, "XFRMA_MARK failed\n");
			exit(1);
		}
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (req.xspi.info.family == AF_UNSPEC)
		req.xspi.info.family = AF_INET;


	if (rtnl_talk(&rth, &req.n, res_n, sizeof(res_buf)) < 0)
		exit(2);

	if (xfrm_state_print(NULL, res_n, (void *)stdout) < 0) {
		fprintf(stderr, "An error :-)\n");
		exit(1);
	}

	rtnl_close(&rth);

	return 0;
}

static int xfrm_state_filter_match(struct xfrm_usersa_info *xsinfo)
{
/// filter作为一个全局变量
/// 在哪里被改变
/// filter.use在list_or_deleteall里被设置为1
	if (!filter.use)
		return 1;

	if (filter.id_src_mask)
		if (xfrm_addr_match(&xsinfo->saddr, &filter.xsinfo.saddr,
				    filter.id_src_mask))
			return 0;
	if (filter.id_dst_mask)
		if (xfrm_addr_match(&xsinfo->id.daddr, &filter.xsinfo.id.daddr,
				    filter.id_dst_mask))
			return 0;
	if ((xsinfo->id.proto^filter.xsinfo.id.proto)&filter.id_proto_mask)
		return 0;
	if ((xsinfo->id.spi^filter.xsinfo.id.spi)&filter.id_spi_mask)
		return 0;
	if ((xsinfo->mode^filter.xsinfo.mode)&filter.mode_mask)
		return 0;
	if ((xsinfo->reqid^filter.xsinfo.reqid)&filter.reqid_mask)
		return 0;
	if (filter.state_flags_mask)
		if ((xsinfo->flags & filter.xsinfo.flags) == 0)
			return 0;

	return 1;
}

/// 从名字来看是打印sa信息
int xfrm_state_print(const struct sockaddr_nl *who, struct nlmsghdr *n,
		     void *arg)
{
/// 结构体类型，文件
	FILE *fp = (FILE *)arg;
	struct rtattr *tb[XFRMA_MAX+1];
	struct rtattr *rta;
/// 	
	struct xfrm_usersa_info *xsinfo = NULL;
	struct xfrm_user_expire *xexp = NULL;
	struct xfrm_usersa_id	*xsid = NULL;
	int len = n->nlmsg_len;

/// 消息类型只有是添加、删除、更新和过期
/// 的时候才会打印相关信息
/// 这里出现的问题是
/// 我们发送的消息类型是GETSA，那么内核一定会返回如下类型吗
/// 那么，内核是如何处理的
	if (n->nlmsg_type != XFRM_MSG_NEWSA &&
	    n->nlmsg_type != XFRM_MSG_DELSA &&
	    n->nlmsg_type != XFRM_MSG_UPDSA &&
	    n->nlmsg_type != XFRM_MSG_EXPIRE) {
		fprintf(stderr, "Not a state: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

/// 接下来根据消息类型获取其数据部分
	if (n->nlmsg_type == XFRM_MSG_DELSA) {
		/* Dont blame me for this .. Herbert made me do it */
/// 获取nlmsg消息体数据字段
/// 如果是删除sa的话，这样处理
		xsid = NLMSG_DATA(n);
		len -= NLMSG_SPACE(sizeof(*xsid));
	} 
/// 如果消息类型是sa过期的话，这样处理
/// sa过期是什么意思，怎么处理？
/// 只是打印消息吗
	else if (n->nlmsg_type == XFRM_MSG_EXPIRE) {
		xexp = NLMSG_DATA(n);
		xsinfo = &xexp->state;
		len -= NLMSG_SPACE(sizeof(*xexp));
	} else {
		xexp = NULL;
		xsinfo = NLMSG_DATA(n);
		len -= NLMSG_SPACE(sizeof(*xsinfo));
	}

/// 消息长度
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

/// 为什么xsinfo为空就返回，
/// 后面的判断条件待看
	if (xsinfo && !xfrm_state_filter_match(xsinfo))
		return 0;

	if (n->nlmsg_type == XFRM_MSG_DELSA)
		fprintf(fp, "Deleted ");
	else if (n->nlmsg_type == XFRM_MSG_UPDSA)
		fprintf(fp, "Updated ");
	else if (n->nlmsg_type == XFRM_MSG_EXPIRE)
		fprintf(fp, "Expired ");

	if (n->nlmsg_type == XFRM_MSG_DELSA)
/// 返回xsid信息
		rta = XFRMSID_RTA(xsid);
	else if (n->nlmsg_type == XFRM_MSG_EXPIRE)
/// 返回xexp信息
		rta = XFRMEXP_RTA(xexp);
	else
///	返回xsinfo消息
		rta = XFRMS_RTA(xsinfo);

/// 属性处理完成，结果存放在tb里
	parse_rtattr(tb, XFRMA_MAX, rta, len);

/// XFRMA_MAX表示xfrm属性最大值

	if (n->nlmsg_type == XFRM_MSG_DELSA) {
		/* xfrm_policy_id_print(); */

		if (!tb[XFRMA_SA]) {
			fprintf(stderr, "Buggy XFRM_MSG_DELSA: no XFRMA_SA\n");
			return -1;
		}
		if (RTA_PAYLOAD(tb[XFRMA_SA]) < sizeof(*xsinfo)) {
			fprintf(stderr, "Buggy XFRM_MSG_DELPOLICY: too short XFRMA_POLICY len\n");
			return -1;
		}
		xsinfo = RTA_DATA(tb[XFRMA_SA]);
	}

	xfrm_state_info_print(xsinfo, tb, fp, NULL, NULL);

	if (n->nlmsg_type == XFRM_MSG_EXPIRE) {
		fprintf(fp, "\t");
		fprintf(fp, "hard %u", xexp->hard);
		fprintf(fp, "%s", _SL_);
	}

	if (oneline)
		fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static int xfrm_state_get_or_delete(int argc, char **argv, int delete)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr	n;
		struct xfrm_usersa_id	xsid;
		char			buf[RTA_BUF_SIZE];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsid)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = delete ? XFRM_MSG_DELSA : XFRM_MSG_GETSA,
		.xsid.family = preferred_family,
	};
	struct xfrm_id id;
	char *idp = NULL;
	struct xfrm_mark mark = {0, 0};

	while (argc > 0) {
		xfrm_address_t saddr;

		if (strcmp(*argv, "mark") == 0) {
			xfrm_parse_mark(&mark, &argc, &argv);
		} else {
			if (idp)
				invarg("unknown", *argv);
			idp = *argv;

			/* ID */
			memset(&id, 0, sizeof(id));
			memset(&saddr, 0, sizeof(saddr));
			xfrm_id_parse(&saddr, &id, &req.xsid.family, 0,
				      &argc, &argv);

			memcpy(&req.xsid.daddr, &id.daddr, sizeof(req.xsid.daddr));
			req.xsid.spi = id.spi;
			req.xsid.proto = id.proto;

			addattr_l(&req.n, sizeof(req.buf), XFRMA_SRCADDR,
				  (void *)&saddr, sizeof(saddr));
		}

		argc--; argv++;
	}

	if (mark.m & mark.v) {
		int r = addattr_l(&req.n, sizeof(req.buf), XFRMA_MARK,
				  (void *)&mark, sizeof(mark));
		if (r < 0) {
			fprintf(stderr, "XFRMA_MARK failed\n");
			exit(1);
		}
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (req.xsid.family == AF_UNSPEC)
		req.xsid.family = AF_INET;

	if (delete) {
		if (rtnl_talk(&rth, &req.n, NULL, 0) < 0)
			exit(2);
	} else {
		char buf[NLMSG_BUF_SIZE] = {};
		struct nlmsghdr *res_n = (struct nlmsghdr *)buf;

		if (rtnl_talk(&rth, &req.n, res_n, sizeof(req)) < 0)
			exit(2);

		if (xfrm_state_print(NULL, res_n, (void *)stdout) < 0) {
			fprintf(stderr, "An error :-)\n");
			exit(1);
		}
	}

	rtnl_close(&rth);

	return 0;
}

/*
 * With an existing state of nlmsg, make new nlmsg for deleting the state
 * and store it to buffer.
 */
static int xfrm_state_keep(const struct sockaddr_nl *who,
			   struct nlmsghdr *n,
			   void *arg)
{
	struct xfrm_buffer *xb = (struct xfrm_buffer *)arg;
	struct rtnl_handle *rth = xb->rth;
	struct xfrm_usersa_info *xsinfo = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct nlmsghdr *new_n;
	struct xfrm_usersa_id *xsid;

	if (n->nlmsg_type != XFRM_MSG_NEWSA) {
		fprintf(stderr, "Not a state: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*xsinfo));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (!xfrm_state_filter_match(xsinfo))
		return 0;

	if (xb->offset > xb->size) {
		fprintf(stderr, "State buffer overflow\n");
		return -1;
	}

	new_n = (struct nlmsghdr *)(xb->buf + xb->offset);
	new_n->nlmsg_len = NLMSG_LENGTH(sizeof(*xsid));
	new_n->nlmsg_flags = NLM_F_REQUEST;
	new_n->nlmsg_type = XFRM_MSG_DELSA;
	new_n->nlmsg_seq = ++rth->seq;

	xsid = NLMSG_DATA(new_n);
	xsid->family = xsinfo->family;
	memcpy(&xsid->daddr, &xsinfo->id.daddr, sizeof(xsid->daddr));
	xsid->spi = xsinfo->id.spi;
	xsid->proto = xsinfo->id.proto;

	addattr_l(new_n, xb->size, XFRMA_SRCADDR, &xsinfo->saddr,
		  sizeof(xsid->daddr));

	xb->offset += new_n->nlmsg_len;
	xb->nlmsg_count++;

	return 0;
}

static int xfrm_state_list_or_deleteall(int argc, char **argv, int deleteall)
{
	char *idp = NULL;
	struct rtnl_handle rth;

/// filter用完应该被初始化？
/// 这是一个xfrm_filter结构体
/// 为什么用到这样一个结构
	if (argc > 0)
		filter.use = 1;
	filter.xsinfo.family = preferred_family;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
/// 用于设置filter.xsinfo.mode
			xfrm_mode_parse(&filter.xsinfo.mode, &argc, &argv);
/// 有mode参数就设置该参数
			filter.mode_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "reqid") == 0) {
			NEXT_ARG();
			xfrm_reqid_parse(&filter.xsinfo.reqid, &argc, &argv);

			filter.reqid_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "flag") == 0) {
			NEXT_ARG();
			xfrm_state_flag_parse(&filter.xsinfo.flags, &argc, &argv);

			filter.state_flags_mask = XFRM_FILTER_MASK_FULL;

		} else {
/// 遇到参数列表		中没能识别的部分
			if (idp)
				invarg("unknown", *argv);
			idp = *argv;

			/* ID */
			xfrm_id_parse(&filter.xsinfo.saddr, &filter.xsinfo.id,
				      &filter.xsinfo.family, 1, &argc, &argv);
			if (preferred_family == AF_UNSPEC)
				preferred_family = filter.xsinfo.family;
		}
		argc--; argv++;
	}
/// filter处理完成	
/// 哈，这里处理套接绑定和连接
	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

/// 本函数的第三个参数用来区分是deleteall还是list
	if (deleteall) {
		struct xfrm_buffer xb;
		char buf[NLMSG_DELETEALL_BUF_SIZE];
		int i;

		xb.buf = buf;
		xb.size = sizeof(buf);
		xb.rth = &rth;

		for (i = 0; ; i++) {
			struct {
				struct nlmsghdr n;
				char buf[NLMSG_BUF_SIZE];
			} req = {
				.n.nlmsg_len = NLMSG_HDRLEN,
				.n.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
				.n.nlmsg_type = XFRM_MSG_GETSA,
				.n.nlmsg_seq = rth.dump = ++rth.seq,
			};

			xb.offset = 0;
			xb.nlmsg_count = 0;

			if (show_stats > 1)
				fprintf(stderr, "Delete-all round = %d\n", i);

			if (rtnl_send(&rth, (void *)&req, req.n.nlmsg_len) < 0) {
				perror("Cannot send dump request");
				exit(1);
			}

			if (rtnl_dump_filter(&rth, xfrm_state_keep, &xb) < 0) {
				fprintf(stderr, "Delete-all terminated\n");
				exit(1);
			}
			if (xb.nlmsg_count == 0) {
				if (show_stats > 1)
					fprintf(stderr, "Delete-all completed\n");
				break;
			}

			if (rtnl_send_check(&rth, xb.buf, xb.offset) < 0) {
				perror("Failed to send delete-all request\n");
				exit(1);
			}
			if (show_stats > 1)
				fprintf(stderr, "Delete-all nlmsg count = %d\n", xb.nlmsg_count);

			xb.offset = 0;
			xb.nlmsg_count = 0;
		}

	} 
/// 既然不是deleteall 就是listall
/// 不是listall而是list,根据filter列出相关的数据类型
	else {
/// 这里处理list
/// 这个结构定义在linux/xfrm.h文件中	
		struct xfrm_address_filter addrfilter = {
			.saddr = filter.xsinfo.saddr,
			.daddr = filter.xsinfo.id.daddr,
			.family = filter.xsinfo.family,
			.splen = filter.id_src_mask,
			.dplen = filter.id_dst_mask,
		};
		struct {
/// 这个结构一定要记住		
			struct nlmsghdr n;
/// #define NLMSG_BUF_SIZE 4096			
/// 4M大小
			char buf[NLMSG_BUF_SIZE];
		} req = {
			.n.nlmsg_len = NLMSG_HDRLEN,
/// dump和request标志位都有哪些作用呢			
/// 估计dump消息就是告诉内核dump一些消息出来
/// 内核看到dump后在查看具体需要dump出哪些内容
			.n.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
/// xfrm_msg_getsa是获取sa的意思
/// 记得这里用的消息类型是XFRM_MSG_GETSA
			.n.nlmsg_type = XFRM_MSG_GETSA,
/// 这里rth.dump & rth.seq等于nlmsg_seq为什么呢
/// 哈，rth.dump在这里配置
			.n.nlmsg_seq = rth.dump = ++rth.seq,
		};

/// 在这里构造消息内容
/// 先处理最小功能集，
/// 即参数最少的情况
		if (filter.xsinfo.id.proto)
			addattr8(&req.n, sizeof(req), XFRMA_PROTO,
				 filter.xsinfo.id.proto);
/// 添加payload，记住属性类型				 
		addattr_l(&req.n, sizeof(req), XFRMA_ADDRESS_FILTER,
			  &addrfilter, sizeof(addrfilter));
/// 发送消息
/// 这里直接调用rtnl_send，
/// 那么套接字绑定，连接应该在之前处理完毕。
		if (rtnl_send(&rth, (void *)&req, req.n.nlmsg_len) < 0) {
			perror("Cannot send dump request");
			exit(1);
		}
/// xfrm_state_print 是一个函数，在这里当作一个参数传递过去
/// 消息发送之后应该会有处理接收的过程
/// 因为发送到内核的消息类型是NLM_F_DUMP，所以这里用dump_filter来处理
/// 这里rtnl_dump_filter是一个宏定义，指向另一个函数
		if (rtnl_dump_filter(&rth, xfrm_state_print, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
	}

	rtnl_close(&rth);

	exit(0);
}

static int print_sadinfo(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
///指向负载
	__u32 *f = NLMSG_DATA(n);
	struct rtattr *tb[XFRMA_SAD_MAX+1];
	struct rtattr *rta;
	__u32 *cnt;

///消息头部和负载长度
	int len = n->nlmsg_len;

///NLMSG_LENGTH返回len+nlmsghdr首部长度
	len -= NLMSG_LENGTH(sizeof(__u32));
///len为负载长度	
	if (len < 0) {
		fprintf(stderr, "SADinfo: Wrong len %d\n", len);
		return -1;
	}

/***
    struct rtattr {
        unsigned short  rta_len;
        unsigned short  rta_type;
    };
***/
///返回rta结构 
	rta = XFRMSAPD_RTA(f);
	parse_rtattr(tb, XFRMA_SAD_MAX, rta, len);

	if (tb[XFRMA_SAD_CNT]) {
		fprintf(fp, "\t SAD");
		cnt = (__u32 *)RTA_DATA(tb[XFRMA_SAD_CNT]);
		fprintf(fp, " count %d", *cnt);
	} else {
		fprintf(fp, "BAD SAD info returned\n");
		return -1;
	}

	if (show_stats) {
		if (tb[XFRMA_SAD_HINFO]) {
			struct xfrmu_sadhinfo *si;

			if (RTA_PAYLOAD(tb[XFRMA_SAD_HINFO]) < sizeof(*si)) {
				fprintf(fp, "BAD SAD length returned\n");
				return -1;
			}

			si = RTA_DATA(tb[XFRMA_SAD_HINFO]);
			fprintf(fp, " (buckets ");
			fprintf(fp, "count %d", si->sadhcnt);
			fprintf(fp, " Max %d", si->sadhmcnt);
			fprintf(fp, ")");
		}
	}
	fprintf(fp, "\n");

	return 0;
}

static int xfrm_sad_getinfo(int argc, char **argv)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr			n;
		__u32				flags;
		char				ans[64];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.flags)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = XFRM_MSG_GETSADINFO,
		.flags = 0XFFFFFFFF,
	};

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (rtnl_talk(&rth, &req.n, &req.n, sizeof(req)) < 0)
		exit(2);

	print_sadinfo(&req.n, (void *)stdout);

	rtnl_close(&rth);

	return 0;
}

static int xfrm_state_flush(int argc, char **argv)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr			n;
		struct xfrm_usersa_flush	xsf;
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsf)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = XFRM_MSG_FLUSHSA,
	};
	char *protop = NULL;

	while (argc > 0) {
		if (strcmp(*argv, "proto") == 0) {
			int ret;

			if (protop)
				duparg("proto", *argv);
			protop = *argv;

			NEXT_ARG();

			ret = xfrm_xfrmproto_getbyname(*argv);
			if (ret < 0)
				invarg("XFRM-PROTO value is invalid", *argv);

			req.xsf.proto = (__u8)ret;
		} else
			invarg("unknown", *argv);

		argc--; argv++;
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (show_stats > 1)
		fprintf(stderr, "Flush state with XFRM-PROTO value \"%s\"\n",
			strxf_xfrmproto(req.xsf.proto));

	if (rtnl_talk(&rth, &req.n, NULL, 0) < 0)
		exit(2);

	rtnl_close(&rth);

	return 0;
}

int do_xfrm_state(int argc, char **argv)
{
	if (argc < 1)
		return xfrm_state_list_or_deleteall(0, NULL, 0);

	if (matches(*argv, "add") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, 0,
					 argc-1, argv+1);
	if (matches(*argv, "update") == 0)
		return xfrm_state_modify(XFRM_MSG_UPDSA, 0,
					 argc-1, argv+1);
	if (matches(*argv, "allocspi") == 0)
		return xfrm_state_allocspi(argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return xfrm_state_get_or_delete(argc-1, argv+1, 1);
	if (matches(*argv, "deleteall") == 0 || matches(*argv, "delall") == 0)
		return xfrm_state_list_or_deleteall(argc-1, argv+1, 1);
	if (matches(*argv, "list") == 0 || matches(*argv, "show") == 0
	    || matches(*argv, "lst") == 0)
/// list 和 get有什么区别	 
		return xfrm_state_list_or_deleteall(argc-1, argv+1, 0);
	if (matches(*argv, "get") == 0)
		return xfrm_state_get_or_delete(argc-1, argv+1, 0);
	if (matches(*argv, "flush") == 0)
		return xfrm_state_flush(argc-1, argv+1);
	if (matches(*argv, "count") == 0) {
		return xfrm_sad_getinfo(argc, argv);
	}
	if (matches(*argv, "help") == 0)
		usage();
	fprintf(stderr, "Command \"%s\" is unknown, try \"ip xfrm state help\".\n", *argv);
	exit(-1);
}
