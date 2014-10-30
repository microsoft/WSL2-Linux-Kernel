#include <linux/export.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>

/* This function exists only for tap drivers that must support broken
 * clients requesting UFO without specifying an IPv6 fragment ID.
 *
 * This is similar to ipv6_select_ident() but we use an independent hash
 * seed to limit information leakage.
 */
void ipv6_proxy_select_ident(struct sk_buff *skb)
{
	static u32 ip6_proxy_idents_hashrnd __read_mostly;
	static bool hashrnd_initialized = false;
	struct in6_addr buf[2];
	struct in6_addr *addrs;
	u32 hash, id;

	addrs = skb_header_pointer(skb,
				   skb_network_offset(skb) +
				   offsetof(struct ipv6hdr, saddr),
				   sizeof(buf), buf);
	if (!addrs)
		return;

	if (unlikely(!hashrnd_initialized)) {
		hashrnd_initialized = true;
		get_random_bytes(&ip6_proxy_idents_hashrnd,
				 sizeof(ip6_proxy_idents_hashrnd));
	}
	hash = __ipv6_addr_jhash(&addrs[1], ip6_proxy_idents_hashrnd);
	hash = __ipv6_addr_jhash(&addrs[0], hash);

	id = ip_idents_reserve(hash, 1);
	skb_shinfo(skb)->ip6_frag_id = htonl(id);
}
EXPORT_SYMBOL_GPL(ipv6_proxy_select_ident);
