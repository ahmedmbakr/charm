'''

| From: "D. Boneh, C. Gentry, B. Lynn, H. Shacham: Aggregate and Verifiably Encrypted Signatures from Bilinear Maps"
| Published in: Journal of Cryptology 2004
| Available from: https://crypto.stanford.edu/~dabo/pubs/papers/aggreg.pdf
| Notes:

* type:           signature (identity-based)
* setting:        bilinear groups (asymmetric)

:Authors:    Ahmed Bakr
:Date:       02/2023
 '''
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import *
from charm.schemes.pksig.pksig_bls04 import BLS01
from functools import reduce

debug = False


class AVES(BLS01):
    def __init__(self, groupObj):
        BLS01.__init__(self, groupObj)

    def aggregate(self, list_of_individual_signatures):
        """
        This function aggregates all the signatures by multiplying all of them to produce a short aggregated signature
        """
        aggregated_signature = list_of_individual_signatures[0] # you cannot initialize the value with 1 first, because you will be multiplying int with a point, so an error will be raised in this case
        for i in range(len(list_of_individual_signatures), 1):
            aggregated_signature = aggregated_signature * list_of_individual_signatures[i]

        return aggregated_signature

    def aggregation_verification(self, aggregated_signature, list_of_public_keys, list_of_messages):
        """
        This function returns Ture if the aggregated verification is verified
        """
        list_of_individual_signatures = []
        for a_pk, a_message in zip(list_of_public_keys, list_of_messages):
            M = self.dump(a_message)
            h = self.group.hash(M, G1)
            individual_sig = pair(h, a_pk['g^x'])
            list_of_individual_signatures.append(individual_sig)
        rhs_value = list_of_individual_signatures[0]
        for i in range(len(list_of_individual_signatures), 1):
            rhs_value = rhs_value * list_of_individual_signatures[i]
        g = list_of_public_keys[0]['g'] # the generator is the same for all keys
        if pair(aggregated_signature, g) == rhs_value:
            return True
        return False


def main():
    groupObj = PairingGroup('MNT224')
    num_users = 3
    messages = ["hello user 1", "hello user 2", "hello user 3"] # num users has to match the number of messages
    assert num_users == len(messages), "Number of messages has to match the number of users because each user has to sign a distinct message"

    users_public_keys = []
    users_signatures = []
    generic_g = None
    for i in range(num_users):
        bls = BLS01(groupObj)
        (pk, sk) = bls.keygen(generic_g)
        if not generic_g:
            generic_g = pk['g']
        users_public_keys.append(pk)
        sig = bls.sign(sk['x'], messages[i]) # The signature is a point (x, y) on the curve

        users_signatures.append(sig)

        if debug: print("Message: for user {}: {}".format(i, messages[i]))
        if debug: print("Signature: '%s'" % sig)

    aves = AVES(groupObj)
    aggregated_signature = aves.aggregate(users_signatures)
    if debug: print("Aggregated Signature: '%s'" % aggregated_signature)
    assert aves.aggregation_verification(aggregated_signature, users_public_keys, messages), "Failure!!!"
    if debug: print('SUCCESS!!! Aggregated signature verified successfully')


def attack_when_two_users_sign_same_message():
    groupObj = PairingGroup('MNT224')
    alice = BLS01(groupObj)
    (alice_pk, alice_sk) = alice.keygen()
    bob = BLS01(groupObj)
    (bob_pk, bob_sk) = alice.keygen()
    negative_1_group_element = bob.dump(-1)
    negative_1_group_element = bob.group.hash(negative_1_group_element, G1)

    bob_forged_pk = bob_pk * (G1/alice_pk)

    message = "Bob will sign this message, but the aggregated signature will act if alice and bob both signed it"
    bob_sig = bob.sign(bob_sk['x'], message)

    aves = AVES(groupObj)
    users_public_keys = [alice_pk, bob_forged_pk]
    messages = [message, message]
    assert aves.aggregation_verification(bob_sig, users_public_keys, messages), "Failure!!!"
    if debug: print('SUCCESS!!! Aggregated signature verified successfully')


if __name__ == "__main__":
    debug = True
    main()
    # attack_when_two_users_sign_same_message()