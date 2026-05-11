from test_framework.utils import BitcoinBackend


class Bip157(BitcoinBackend):
    def __init__(self, bitcoind):
        self.bitcoind = bitcoind

    def startup(self):
        self.bitcoind.wait_for_blockfilter_index()

    def cleanup(self):
        pass

    def append_to_lianad_conf(self, conf_file):
        with open(conf_file, "a") as f:
            f.write("[bip157_config]\n")
            f.write(f"peers = ['127.0.0.1:{self.bitcoind.p2pport}']\n")
            f.write("required_peers = 1\n")
            f.write("whitelist_only = true\n")
