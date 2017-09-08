/// By Fanxiushu 2013-01-11

#include "vnetwk.h"


struct vnetwk_t*  vwk_array[ VNETWK_COUNT ];

static int vwk_count = 1;
static int vwk_devid = 0; 

static struct file_operations vwk_fops = {
    .open     = vwk_chr_open,
    .release  = vwk_chr_release,
    .read     = vwk_chr_read,
    .write    = vwk_chr_write,
    .ioctl    = vwk_chr_ioctl,
    .poll     = vwk_chr_poll,
};

static int vwk_netdev_init( struct net_device* dev )
{
    struct netdev_priv_t* priv;

    priv = (struct netdev_priv_t*)netdev_priv(dev );
    /// set func 
    dev->open = vwk_net_open;
    dev->stop = vwk_net_stop;
    dev->do_ioctl = vwk_net_ioctl;
    dev->get_stats = vwk_net_stats;
    dev->tx_timeout = vwk_net_tx_timeout;
    dev->set_mac_address = vwk_net_set_mac_address;
    dev->change_mtu = vwk_net_change_mtu;
    dev->hard_start_xmit = vwk_net_start_xmit;

    ///
    ether_setup( dev ); 

    random_ether_addr(dev->dev_addr);
    ///
    printk( KERN_ALERT" init netdev [index=%d] OK.\n", priv->vwk->index );

    return 0;

}
static int vwk_netdev_create( struct vnetwk_t* vwk)
{
    char name[15]; int result;
    struct netdev_priv_t* priv;

    sprintf( name, "vnetwk%d", vwk->index ); 
    vwk->net_dev = alloc_netdev( sizeof( struct netdev_priv_t), name , ether_setup ); 
    if( !vwk->net_dev ) {
        printk(KERN_ALERT" alloc_netdev err, index=%d\n", vwk->index );
        return -1;
    }
    priv = (struct netdev_priv_t*)netdev_priv( vwk->net_dev ); 
    priv->vwk = vwk; 
    vwk->net_dev->init = vwk_netdev_init; 

    result = register_netdev( vwk->net_dev ); 
    if( result < 0){
        printk(KERN_ALERT" register_netdev err <%d> index=%d\n", result, vwk->index);
        free_netdev( vwk->net_dev ); 
        vwk->net_dev = NULL;
        return -1; 
    }
    ///
    return 0; 
}
static int vwk_netdev_close( struct vnetwk_t* vwk)
{
    if( !vwk || !vwk->net_dev ) return -1; 
    ////清空SKB队列
    skb_queue_purge( &vwk->skb_q ); 

    unregister_netdev( vwk->net_dev ); 

    free_netdev( vwk->net_dev ); 
    vwk->net_dev = NULL; 
    return 0;
}

static int vwk_device_create_index( int index )
{
    int result;
    dev_t devt; 
    struct vnetwk_t* vwk = NULL;
    struct device* vwk_dev= NULL;
    char tmp_str[20];
    
    devt = MKDEV( vwk_devid, index ); //

    vwk = (struct vnetwk_t*)kzalloc( sizeof( struct vnetwk_t), GFP_KERNEL ); 
    if( !vwk ){
        printk(KERN_ALERT"kzalloc error.\n");
        return -1; 
    }

    vwk->index = index;

    skb_queue_head_init( &vwk->skb_q );
    init_waitqueue_head( &vwk->wait_q );

    /////创建网路设备
    if( vwk_netdev_create( vwk ) < 0 ) {
        printk(KERN_ALERT"Not Create netdevice.\n");
        kfree( vwk );
        return -1; 
    }

    ///////注册字符设备
    cdev_init( &vwk->chr_dev, &vwk_fops ); 
    vwk->chr_dev.owner = THIS_MODULE;
    vwk->chr_dev.ops = &vwk_fops; 

    result = cdev_add( &vwk->chr_dev, devt, 1 ); 
    if( result ) {
        printk(KERN_NOTICE"cdev_add err <%d>, index=%d\n", result, index );
    }

    ///创建设备节点，为了用户程序能访问
    sprintf( tmp_str, "cls_vnetwk%d", index );
    vwk->vwk_cls = class_create( THIS_MODULE, tmp_str );
    if( !vwk->vwk_cls ){
        printk(KERN_ALERT"class_create err, index=%d\n", index );
        goto E; 
    }
    vwk_dev = device_create( vwk->vwk_cls, NULL, devt, "vnetwk%d", index ); 
    if( !vwk_dev ){
        printk( KERN_ALERT"device_create err, index=%d\n", index);
    }

    ////
    vwk_array[ index ] = vwk; 

    return 0;

E:
    vwk_netdev_close( vwk );
    cdev_del( &vwk->chr_dev ); 

    if( vwk->vwk_cls ){
        device_destroy( vwk->vwk_cls ,devt ); 
        class_destroy( vwk->vwk_cls ); 
    }

    kfree(vwk ); 

    return -1; 
}
///
static int vwk_device_destroy_index( int index )
{
    struct vnetwk_t* vwk = vwk_array[ index ]; 
    if( !vwk ) return -1; 
    ///
    vwk_netdev_close( vwk );
    cdev_del( &vwk->chr_dev ); 

    if( vwk->vwk_cls ){
        device_destroy( vwk->vwk_cls , MKDEV( vwk_devid, index ) ); 
        class_destroy( vwk->vwk_cls ); 
    }

    ///
    kfree( vwk ); 
    vwk_array[index] = NULL; 
    return 0;
}
static void vwk_device_destroy(void)
{
    int i;
    for( i=0;i<VNETWK_COUNT;++i){
        vwk_device_destroy_index( i ); 
    }
}


static int vnetwk_init(void)
{
    int i; dev_t devt; 
    int result;
    ////
    for(i=0;i<VNETWK_COUNT;++i){
        vwk_array[i] = NULL;
    }
    if( vwk_count < 1 ) vwk_count = 1; 
    if( vwk_count > VNETWK_COUNT ) vwk_count = VNETWK_COUNT;

    ///申请一批设备号，为创建字符设备做准备
    devt = MKDEV( vwk_devid, 0 ); 
    if( vwk_devid ){
        result = register_chrdev_region( devt,  vwk_count, "vnetwk" ); 
    }
    else{
        result = alloc_chrdev_region( &devt, 0, vwk_count, "vnetwk" );
        vwk_devid = MAJOR( devt ); 
    }
    if( result < 0 ){
        printk(KERN_ALERT"register Device ID Error.\n");
        return -1;
    }
    ////
    for(i=0;i< vwk_count;++i){
        if( vwk_device_create_index( i ) < 0 ){
            vwk_device_destroy();
            unregister_chrdev_region( MKDEV( vwk_devid, 0 ), vwk_count ); 
            ///
            printk(KERN_ALERT"can not create %d device.\n", i );
            return -1; 
        }
    }
    ////////////////

    return 0;
}

static void vnetwk_exit(void)
{
    vwk_device_destroy(); 
    ////
    unregister_chrdev_region( MKDEV( vwk_devid, 0), vwk_count ); 
    
    printk(KERN_INFO"vnetwk_exit. \n ");

}

module_param( vwk_count, int, S_IRUGO );
module_param( vwk_devid, int, S_IRUGO );

module_init( vnetwk_init);
module_exit( vnetwk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fanxiushu");
MODULE_DESCRIPTION("A Virtual Network Card Driver");