from dataclasses import dataclass

from bip32 import BIP32, HARDENED_INDEX
from bip32.utils import _pubkey_to_fingerprint


DERIVE_THEN_AGGREGATE = "derive-then-aggregate"
AGGREGATE_THEN_DERIVE = "aggregate-then-derive"

SPEND_KIND_KEY = "key"
SPEND_KIND_BC = "bc"
SPEND_KIND_AC = "ac"

CSV_BY_SPEND_KIND = {
    SPEND_KIND_BC: 1,
    SPEND_KIND_AC: 100,
}

BRANCHES_BY_SPEND_KIND = {
    SPEND_KIND_KEY: (0, 1),
    SPEND_KIND_AC: (2, 3),
    SPEND_KIND_BC: (4, 5),
}

PARTICIPANTS_BY_SPEND_KIND = {
    SPEND_KIND_KEY: ("a", "b"),
    SPEND_KIND_AC: ("a", "c"),
    SPEND_KIND_BC: ("b", "c"),
}

ROOT_PATHS = {
    ("a", SPEND_KIND_KEY): [48, 1, 0, 2],
    ("b", SPEND_KIND_KEY): [48, 1, 1, 2],
    ("a", SPEND_KIND_AC): [48, 1, 10, 2],
    ("c", SPEND_KIND_AC): [48, 1, 2, 2],
    ("b", SPEND_KIND_BC): [48, 1, 11, 2],
    ("c", SPEND_KIND_BC): [48, 1, 12, 2],
}

SEEDS = {
    "a": bytes.fromhex("11" * 32),
    "b": bytes.fromhex("22" * 32),
    "c": bytes.fromhex("33" * 32),
}


def hardened(index):
    return index + HARDENED_INDEX


def hardened_path(path):
    return [hardened(index) for index in path]


def origin_path(path):
    return "/" + "/".join(f"{index}'" for index in path)


def branch_suffix(branches, branch_index):
    if branch_index is None:
        return f"/<{branches[0]};{branches[1]}>/*"
    return f"/{branches[branch_index]}/*"


def signer_fingerprint(hd):
    return _pubkey_to_fingerprint(hd.pubkey).hex()


def deterministic_signers():
    return {name: BIP32.from_seed(seed, network="test") for name, seed in SEEDS.items()}


@dataclass(frozen=True)
class DescriptorBodies:
    multipath: str
    receive: str
    change: str


class MuSig2DescriptorFactory:
    def __init__(self):
        self.signers = deterministic_signers()

    def _descriptor_key(
        self, signer_name, spend_kind, branch_index, private_signers, with_branch=True
    ):
        hd = self.signers[signer_name]
        root_path = ROOT_PATHS[(signer_name, spend_kind)]
        derivation_path = hardened_path(root_path)
        xkey = (
            hd.get_xpriv_from_path(derivation_path)
            if signer_name in private_signers
            else hd.get_xpub_from_path(derivation_path)
        )
        key = f"[{signer_fingerprint(hd)}{origin_path(root_path)}]{xkey}"
        if with_branch:
            key += branch_suffix(BRANCHES_BY_SPEND_KIND[spend_kind], branch_index)
        return key

    def _musig_expression(self, spend_kind, mode, branch_index, private_signers):
        participants = [
            self._descriptor_key(
                name, spend_kind, None, private_signers, with_branch=False
            )
            if mode == AGGREGATE_THEN_DERIVE
            else self._descriptor_key(name, spend_kind, branch_index, private_signers)
            for name in PARTICIPANTS_BY_SPEND_KIND[spend_kind]
        ]
        expr = f"musig({','.join(participants)})"
        if mode == AGGREGATE_THEN_DERIVE:
            expr += branch_suffix(BRANCHES_BY_SPEND_KIND[spend_kind], branch_index)
        return expr

    def descriptor_body(self, mode, branch_index=None, private_signers=frozenset()):
        primary = self._musig_expression(
            SPEND_KIND_KEY, mode, branch_index, private_signers
        )
        recovery_bc = self._musig_expression(
            SPEND_KIND_BC, mode, branch_index, private_signers
        )
        recovery_ac = self._musig_expression(
            SPEND_KIND_AC, mode, branch_index, private_signers
        )
        return (
            f"tr({primary},{{"
            f"and_v(v:pk({recovery_bc}),older({CSV_BY_SPEND_KIND[SPEND_KIND_BC]})),"
            f"and_v(v:pk({recovery_ac}),older({CSV_BY_SPEND_KIND[SPEND_KIND_AC]}))"
            f"}})"
        )

    def descriptor_bodies(self, mode, private_signers=frozenset()):
        return DescriptorBodies(
            multipath=self.descriptor_body(mode, None, private_signers),
            receive=self.descriptor_body(mode, 0, private_signers),
            change=self.descriptor_body(mode, 1, private_signers),
        )
