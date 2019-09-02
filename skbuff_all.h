typedef unsigned char __u8;
typedef unsigned short __u16;
typedef __u16 __be16;
typedef unsigned int   __u32;
typedef unsigned int   __be32;
typedef unsigned char *sk_buff_data_t;
typedef __16 __sum16;


/** include/uapi/linux/ip.h  **/
struct iphdr {
// #if defined(__LITTLE_ENDIAN_BITFIELD)
// __u8	ihl:4,
//		version:4;
// #elif defined (__BIG_ENDIAN_BITFIELD)
// 	__u8	version:4,
//   		ihl:4;
// #else
// #error	"Please fix <asm/byteorder.h>"
// #endif
        __u8 hl_version;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};




/** include/uapi/linux/tcp.h  **/
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
        // We are little endian
        // #if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 flags;
        /*
        __u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
        */
// #elif defined(__BIG_ENDIAN_BITFIELD)
//	__u16	doff:4,
//		res1:4,
//		cwr:1,
//		ece:1,
//		urg:1,
//		ack:1,
//		psh:1,
//		rst:1,
//		syn:1,
//		fin:1;
//#else
//#error	"Adjust your <asm/byteorder.h> defines"
//#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};







typedef struct {
        int counter;
} atomic_t;
typedef int refcount_t; // struct refcount_struct { atomic_t refs; } refcount_t;


struct sk_buff {
        char                filler[40]; // Fillter data
	char			cb[48]; // 88 
        char               filler0[16];
	unsigned long		 _nfct; // 8 bytes, 112 total
	unsigned int		len,
				data_len;
	__u16			mac_len,
				hdr_len;

	/* Following fields are _not_ copied in __copy_skb_header()
	 * Note that queue_mapping is here mostly to fill a hole.
	 */
	__u16			queue_mapping;

/* if you move cloned around you also must adapt those constants */
	__u8			__cloned_offset[0];
	// r2 can't handle bit specific fields
        /*
        __u8			cloned:1,
				nohdr:1,
				fclone:2,
				peeked:1,
				head_frag:1,
				pfmemalloc:1;
        */
	__u8			active_extensions;
	/* fields enclosed in headers_start/headers_end are copied
	 * using a single memcpy() in __copy_skb_header()
	/* private: */
	__u32			headers_start[0];
	/* public: */

	__u8			__pkt_type_offset[0];
        /*
        __u8			pkt_type:3;
	__u8			ignore_df:1;
	__u8			nf_trace:1;
	__u8			ip_summed:2;
	__u8			ooo_okay:1;

	__u8			l4_hash:1;
	__u8			sw_hash:1;
	__u8			wifi_acked_valid:1;
	__u8			wifi_acked:1;
	__u8			no_fcs:1;
	/* Indicates the inner headers are valid in the skbuff.
	__u8			encapsulation:1;
	__u8			encap_hdr_csum:1;
	__u8			csum_valid:1;
        */
        __u8			__pkt_vlan_present_offset[0];
        /*
	__u8			vlan_present:1;
	__u8			csum_complete_sw:1;
	__u8			csum_level:2;
	__u8			csum_not_inet:1;
	__u8			dst_pending_confirm:1;
	__u8			ndisc_nodetype:2;

	__u8			ipvs_property:1;
	__u8			inner_protocol_type:1;
	__u8			remcsum_offload:1;
        __u8			tc_skip_classify:1;
	__u8			tc_at_ingress:1;
	__u8			tc_redirected:1;
	__u8			tc_from_ingress:1;
//#ifdef CONFIG_TLS_DEVICE
//	__u8			decrypted:1;
//#endif
*/
	__u16			tc_index;	/* traffic control index */ 

        char filler2                 [4];
	__u32			priority;
	int			skb_iif;
	__u32			hash;
	__be16			vlan_proto;
	__u16			vlan_tci;
        char filler3[4];
	__u32		secmark;

        char filler4[6];
	__u16			inner_transport_header;
	__u16			inner_network_header;
	__u16			inner_mac_header;

	__be16			protocol;
	__u16			transport_header;
	__u16			network_header;
	__u16			mac_header;

	__u32			headers_end[0];
	sk_buff_data_t		tail;
	sk_buff_data_t		end;
	unsigned char		*head,
				*data;
	unsigned int		truesize;
	refcount_t		users;

	unsigned long		*extensions;
};
