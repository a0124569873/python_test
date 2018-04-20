# Copyright 2014, 6WIND S.A.

class PCICardFamily(object):

    def __init__(self, name, product_ids, vendor_id,
                 required_addons=None, capabilities=None):
        self.name = name
        self.product_ids = product_ids
        self.vendor_id = vendor_id
        self.required_addons = required_addons or []
        self.capabilities = capabilities

    def __str__(self):
        return self.name

class EthernetCapabilities(object):

    def __init__(self, rxq, txq):
        self.rxq = rxq
        self.txq = txq

class CryptoCapabilities(object):

    def __init__(self, option_name, option_mode, pool_size,
                 session_size, context_size):
        self.option_name = option_name
        self.option_mode = option_mode
        self.pool_size = pool_size
        self.context_size = context_size
        self.session_size = session_size

# --------------------------- globals and define -------------------------------
_ALL = [
    PCICardFamily(
        name='Intel Physical EM',
        product_ids=[
            '100e', '100f', '1011', '1010', '1012', '105e', '105f',
            '1060', '10d9', '10da', '10a4', '10d5', '10a5', '10bc',
            '107d', '107e', '107f', '10b9', '109a', '10d3', '10f6'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='Intel Physical IGB',
        product_ids=[
            '10c9', '10e6', '10e7', '10e8', '1526', '150a', '1518',
            '150d', '10a7', '10a9', '10d6', '150e', '150f', '1510',
            '1511', '1516', '1527', '1521', '1522', '1524', '1546',
            '1533', '1534', '1535', '1536', '1537', '1538', '1539',
            '1f40', '1f41', '1f45', '0438', '043a', '043c', '0440'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='Intel Physical IXGBE',
        product_ids=[
            '10b6', '1508', '10c6', '10c7', '10c8', '150b', '10db',
            '10dd', '10ec', '10f1', '10e1', '10f4', '10f7', '1514',
            '1517', '10f8', '000c', '10f9', '10fb', '11a9', '1f72',
            '17d0', '0470', '152a', '1529', '1507', '154d', '154a',
            '1557', '10fc', '151c', '1528', '1560'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='Intel Physical I40',
        product_ids=[
            '1572', '1573', '1574', '157f', '1580', '1581', '1582',
            '1583', '1584', '1585'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='Intel Virtual e1000',
        product_ids=[
            '10ca', '152d', '1520', '152f'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='Intel Virtual ixgbe',
        product_ids=[
            '10ed', '152e', '1515', '1530'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='Intel Virtual i40',
        product_ids=[
            '154c', '1571'
        ],
        vendor_id='8086',
    ),
    PCICardFamily(
        name='virtio',
        product_ids=[
            '1000', '1001', '1002', '1003', '1004', '1005', '1006', '1007',
            '1008', '1009', '100a', '100b', '100c', '100d', '100e', '100f',
            '1010', '1011', '1012', '1013', '1014', '1015', '1016', '1017',
            '1018', '1019', '101a', '101b', '101c', '101d', '101e', '101f',
            '1020', '1021', '1022', '1023', '1024', '1025', '1026', '1027',
            '1028', '1029', '102a', '102b', '102c', '102d', '102e', '102f',
            '1030', '1031', '1032', '1033', '1034', '1035', '1036', '1037',
            '1038', '1039', '103a', '103b', '103c', '103d', '103e', '103f'
        ],
        vendor_id='1af4',
    ),
    PCICardFamily(
        name='oce',
        product_ids=[
            '0720'
        ],
        vendor_id='10df',
        required_addons=[
            'librte_pmd_oce.so'
        ],
    ),
    PCICardFamily(
        name='VMWare',
        product_ids=[
            '07b0'
        ],
        vendor_id='15ad',
        capabilities=EthernetCapabilities(8, 8),
    ),
    PCICardFamily(
        name='FastVnic',
        product_ids=[
            '1110'
        ],
        vendor_id='1af4',
        required_addons=[
            'librte_pmd_fast_vnic.so'
        ],
    ),
    PCICardFamily(
        name='Mellanox',
        product_ids=[
            '1003', '1004', '1007'
        ],
        vendor_id='15b3',
        required_addons=[
            'librte_pmd_mlx4.so'
        ],
    ),
    PCICardFamily(
        name='Nitrox',
        product_ids=[
            '0010', '0011'
        ],
        vendor_id='177d',
        required_addons=[
            'librte_crypto_nitrox.so'
        ],
        capabilities=CryptoCapabilities('nitrox', 1, 640, 128, 768),
    ),
    PCICardFamily(
        name='Intel Quickassist Cavecreek',
        product_ids=[
            '0434'
        ],
        vendor_id='8086',
        required_addons=[
            'librte_crypto_quickassist.so'
        ],
        capabilities=CryptoCapabilities('quickassist', 2, 960, 88, 1280),
    ),
    PCICardFamily(
        name='Intel Quickassist Coletocreek',
        product_ids=[
            '0435'
        ],
        vendor_id='8086',
        required_addons=[
            'librte_crypto_quickassist.so'
        ],
        capabilities=CryptoCapabilities('quickassist', 1, 960, 88, 1280),
    ),
    PCICardFamily(
        name='Intel Multibuffer',
        product_ids=[
            'ffff'     # dummy value as multibuffer crypto is not a PCI card
        ],
        vendor_id='8086',
        required_addons=[
            'librte_crypto_multibuffer.so'
        ],
        capabilities=CryptoCapabilities('multibuffer', 0, 384, 128, 1280),
    ),
]

class CardNotSupported(Exception):
    pass

def find_card_family(vendor_id, product_id):
    """
    Check if PCI card (vendor_id, product_id) is managed by fast path

    :arg string vendor_id:
        vendor id of the PCI card
    :arg string product_id:
        product id of the PCI card
    :returns PCICardFamily card:
        Information relative to the PCI card if supported by fast path, an
        exception otherwise
    """

    for family in _ALL:
        if family.vendor_id == vendor_id and product_id in family.product_ids:
            return family

    raise CardNotSupported('%s:%s' % (vendor_id, product_id))


