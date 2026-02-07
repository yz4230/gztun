#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>
#include <linux/zstd.h>
#include <net/ip.h>
#include <net/rtnetlink.h>

#define DRV_NAME "gztun"
#define ZSTD_COMPRESSION_LEVEL 1
#define BUFSIZE 256
#define TUN_PORT 9999

struct zstd_ctx {
  void *workspace;
  size_t workspace_size;
  zstd_parameters params;
};

static struct zstd_ctx __percpu *zstd_ctx_pool;

struct gztun_struct {
  struct net_device *redirect_dev;
  netdevice_tracker tracker;
};

static void free_gztun_struct(struct gztun_struct *gztun) {
  if (gztun->redirect_dev) {
    netdev_put(gztun->redirect_dev, &gztun->tracker);
    gztun->redirect_dev = NULL;
  }
}

static int check_proto(struct sk_buff *skb) {
  struct iphdr *iph;
  struct udphdr *udph;

  iph = ip_hdr(skb);
  if (iph->protocol != IPPROTO_UDP) {
    return -1;
  }
  udph = udp_hdr(skb);
  if (udph->dest != htons(TUN_PORT)) {
    return -1;
  }

  return 0;
}

static int make_skb_safe(struct sk_buff **pskb) {
  struct sk_buff *skb = *pskb;
  int ret;

  if (skb_shared(skb) || skb_cloned(skb)) {
    struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
    if (!nskb) {
      pr_err("gztun: failed to copy skb\n");
      return -ENOMEM;
    }
    dev_kfree_skb(skb);
    skb = nskb;
    *pskb = skb;
  }

  ret = skb_linearize(skb);
  if (ret != 0) {
    pr_err("gztun: skb_linearize failed: %d\n", ret);
    return ret;
  }

  return 0;
}

static int stretch_skb_size(struct sk_buff *skb, int size_diff) {
  int ret;
  if (size_diff > 0) {
    if (skb_tailroom(skb) < size_diff) {
      ret = pskb_expand_head(skb, 0, size_diff - skb_tailroom(skb), GFP_ATOMIC);
      if (ret != 0) {
        pr_err("gztun: failed to expand skb head\n");
        return ret;
      }
    }
  } else if (size_diff < 0) {
    skb_trim(skb, skb->len + size_diff);
  }
  return 0;
}

static netdev_tx_t gztun_start_xmit(struct sk_buff *skb, struct net_device *dev) {
  struct gztun_struct *gztun;
  struct zstd_ctx *ctx;
  zstd_cctx *cctx;
  int ret;

  u8 dst_buf[BUFSIZE];
  int len_diff, udph_off, payload_off;
  size_t old_size, new_size;

  pr_info("gztun: start_xmit called, len=%u\n", skb->len);

  if (check_proto(skb) != 0) {
    pr_err("gztun: packet is not UDP to port %d, dropping\n", TUN_PORT);
    goto drop;
  }

  udph_off = skb_transport_offset(skb);
  payload_off = udph_off + sizeof(struct udphdr);
  old_size = skb->len - payload_off;

  if ((ret = make_skb_safe(&skb)) != 0) {
    pr_err("gztun: make_skb_safe failed: %d\n", ret);
    goto drop;
  }

  ctx = get_cpu_ptr(zstd_ctx_pool);
  cctx = zstd_init_cctx(ctx->workspace, ctx->workspace_size);
  if (!cctx) {
    pr_err("gztun: failed to initialize zstd cctx\n");
    put_cpu_ptr(zstd_ctx_pool);
    goto drop;
  }

  new_size = zstd_compress_cctx(cctx, dst_buf, BUFSIZE, skb->data + payload_off, old_size, &ctx->params);
  if (zstd_is_error(new_size)) {
    pr_err("gztun: zstd compression failed: %s\n", zstd_get_error_name(new_size));
    zstd_free_cctx(cctx);
    put_cpu_ptr(zstd_ctx_pool);
    goto drop;
  }

  zstd_free_cctx(cctx);
  put_cpu_ptr(zstd_ctx_pool);

  len_diff = new_size - old_size;
  ret = stretch_skb_size(skb, len_diff);
  if (ret != 0) {
    pr_err("gztun: stretch_skb_size failed: %d\n", ret);
    goto drop;
  }

  memcpy(skb->data + payload_off, dst_buf, new_size);
  struct iphdr *iph = (struct iphdr *)skb->data;
  struct udphdr *udph = (struct udphdr *)(skb->data + udph_off);
  udph->len = htons(sizeof(struct udphdr) + new_size);
  iph->tot_len = htons(skb->len);
  udph->check = 0;
  udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP,
                                  csum_partial((char *)udph, ntohs(udph->len), 0));
  iph->check = 0;
  ip_send_check(iph);

  gztun = netdev_priv(dev);
  skb->dev = gztun->redirect_dev;
  dev_queue_xmit(skb);

  pr_info("gztun: packet compressed to %zu bytes and redirected to %s\n", new_size, gztun->redirect_dev->name);
  return NETDEV_TX_OK;

drop:
  dev_kfree_skb(skb);
  return NETDEV_TX_OK;
}

static const struct net_device_ops gztun_netdev_ops = {
    .ndo_start_xmit = gztun_start_xmit,
    .ndo_set_mac_address = eth_mac_addr,
};

static void gztun_setup(struct net_device *dev) {
  ether_setup(dev);

  dev->netdev_ops = &gztun_netdev_ops;

  dev->needs_free_netdev = true;
  dev->flags |= IFF_NOARP;
  eth_hw_addr_random(dev);
}

static int gztun_validate(struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack) {
  if (!tb[IFLA_LINK]) {
    NL_SET_ERR_MSG(extack, "gztun: redirect device (IFLA_LINK) is required");
    return -EINVAL;
  }

  return 0;
}

static int gztun_newlink(struct net_device *dev, struct rtnl_newlink_params *params, struct netlink_ext_ack *extack) {
  pr_info("gztun: newlink called for device %s\n", dev->name);

  struct gztun_struct *gztun;
  struct nlattr **tb;
  struct net_device *link_dev;
  u32 ifindex;
  int err;

  gztun = netdev_priv(dev);
  gztun->redirect_dev = NULL;
  tb = params->tb;

  if (tb[IFLA_LINK]) {
    ifindex = nla_get_u32(tb[IFLA_LINK]);
    link_dev = netdev_get_by_index(params->src_net, ifindex, &gztun->tracker, GFP_KERNEL);
    if (link_dev) {
      gztun->redirect_dev = link_dev;
      pr_info("gztun: linked to device %s\n", link_dev->name);
    } else {
      pr_err("gztun: failed to get device by index %u\n", ifindex);
      return -ENODEV;
    }
  } else {
    pr_err("gztun: no IFLA_LINK attribute provided\n");
    return -EINVAL;
  }

  err = register_netdevice(dev);
  if (err) {
    pr_err("gztun: register_netdev failed: %d\n", err);
    free_gztun_struct(gztun);
  }
  return err;
}

static void gztun_dellink(struct net_device *dev, struct list_head *head) {
  struct gztun_struct *gztun = netdev_priv(dev);
  free_gztun_struct(gztun);
  unregister_netdevice_queue(dev, head);
}

static struct rtnl_link_ops gztun_link_ops = {
    .kind = DRV_NAME,
    .setup = gztun_setup,
    .validate = gztun_validate,
    .newlink = gztun_newlink,
    .dellink = gztun_dellink,
    .priv_size = sizeof(struct gztun_struct),
};

static void free_zstd_ctx_pool(void) {
  int cpu;
  for_each_possible_cpu(cpu) {
    struct zstd_ctx *ctx = per_cpu_ptr(zstd_ctx_pool, cpu);
    if (ctx->workspace) {
      kvfree(ctx->workspace);
      ctx->workspace = NULL;
    }
  }
  free_percpu(zstd_ctx_pool);
  zstd_ctx_pool = NULL;
}

static int __init gztun_netdev_init(void) {
  int err, cpu;
  zstd_parameters params;
  size_t workspace_size;
  pr_info("gztun: initializing\n");

  params = zstd_get_params(ZSTD_COMPRESSION_LEVEL, 0);
  workspace_size = zstd_cstream_workspace_bound(&params.cParams);

  zstd_ctx_pool = alloc_percpu(struct zstd_ctx);
  if (!zstd_ctx_pool)
    return -ENOMEM;

  for_each_possible_cpu(cpu) {
    struct zstd_ctx *ctx = per_cpu_ptr(zstd_ctx_pool, cpu);
    ctx->params = params;
    ctx->workspace_size = workspace_size;
    ctx->workspace = kvmalloc(workspace_size, GFP_KERNEL);
    if (!ctx->workspace) {
      pr_err("gztun: failed to allocate zstd workspace for CPU %d\n", cpu);
      free_zstd_ctx_pool();
      return -ENOMEM;
    }
  }

  err = rtnl_link_register(&gztun_link_ops);
  if (err < 0) {
    pr_err("gztun: failed to register rtnl link ops\n");
    free_zstd_ctx_pool();
    return err;
  }

  return 0;
}

static void __exit gztun_netdev_exit(void) {
  pr_info("gztun: exiting\n");
  rtnl_link_unregister(&gztun_link_ops);
  free_zstd_ctx_pool();
}

module_init(gztun_netdev_init);
module_exit(gztun_netdev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuzuki Ishiyama");
MODULE_DESCRIPTION("Generic ZTUN-like virtual network device");
