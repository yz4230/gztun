#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <net/rtnetlink.h>

#define DRV_NAME	"test"

MODULE_LICENSE("GPL v2");

// Transmit packets
static netdev_tx_t test_xmit(struct sk_buff *skb, struct net_device *dev)
{
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops test_netdev_ops = {
	.ndo_start_xmit		= test_xmit,
//	.ndo_open		= test_open,
//	.ndo_stop		= test_stop,
	.ndo_set_mac_address	= eth_mac_addr,
};

static void test_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &test_netdev_ops;

	// setting parameters 
	dev->needs_free_netdev = true;		// executing free_netdev() when unregister
	dev->flags |= IFF_NOARP;
	eth_hw_addr_random(dev);

}

int test_newlink(struct net *net, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack)
{
	int err = 0;

	err = register_netdevice(dev);

	if(err < 0){
		pr_err("test_netdev: error, register_netdevice\n");
		free_netdev(dev);
	}

	return 0;
}

static struct rtnl_link_ops test_ops = {
	.kind		= DRV_NAME,
	.setup		= test_setup,
	.newlink	= test_newlink,
};

static int __init test_netdev_init(void)
{
	int err = 0;

	err = rtnl_link_register(&test_ops);

	if(err < 0){
		pr_err("test_netdev: error, rtnl_link_register\n");
		return -1;
	}

	return 0;
}


static void __exit test_netdev_exit(void)
{
	rtnl_link_unregister(&test_ops);
}

module_init(test_netdev_init);
module_exit(test_netdev_exit);
