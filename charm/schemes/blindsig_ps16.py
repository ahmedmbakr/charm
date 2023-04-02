'''

| From: "David Pointcheval, Olivier Sanders: Short Randomizable Signatures"
| Published in: Proceedings of the RSA Conference on Topics in Cryptology 2016
| Available from: https://dl.acm.org/doi/10.1007/978-3-319-29485-8_7
| Notes:

* type:           signature (blind signature)
* setting:        bilinear groups (asymmetric)

:Authors:    Ahmed Bakr
:Date:       04/2023
 '''
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import *
from charm.schemes.pksig.pksig_bls04 import BLS01
from functools import reduce
from charm.toolbox.PKSig import PKSig


class PS_Sig(PKSig):

    def __init__(self, groupObj):
        PKSig.__init__(self)
        self.group = groupObj

    def _dump_to_zp_element(self, obj):
        serialized_message = objectToBytes(obj, self.group)
        return self.group.hash(serialized_message) # convert the serialized message to object from Z_p

    def keygen(self):
        """
        This function is used to generate the secret key and the public key of the signer
        """
        print("This is a stub function. Implement it in the child class")

    def sign(self, sk, message):
        """
        This function is used for the signer to sign a message
        Inputs:
            - sk: Secret key of the signer
            - message: message to be signed
        Outputs:
            - sigma: Signature on the message
        """
        print("This is a stub function. Implement it in the child class")

    def verify(self, message, pk, sig) -> bool:
        """
        This function is used for the user to verify a signature on a specific message using the message and the public
        key of the signer.
        Inputs:
            - message: The message
            - pk: Public key
            - sig: signature
        Outputs:
            - True if the signature is valid on the message by the user whose public key is pk
            - False, otherwise
        """
        print("This is a stub function. Implement it in the child class")


class PS_BlindSig(PS_Sig):

    def __init__(self, groupObj):
        PS_Sig.__init__(self, groupObj)

    def keygen(self):
        """
        This function is used to generate the secret key and the public key of the signer
        """
        print("This is a stub function. Implement it in the child class")

    def blind(self, message):
        """
        This function takes a message and blinds it to return a blinded message.
        Inputs:
            - message: message to be blinded
        Outputs:
            - blinded_message: A blinded message
        """
        print("This is a stub function. Implement it in the child class")

    def sign(self, sk, blinded_message):
        """
        This function is used for the signer to sign a message
        Inputs:
            - sk: Secret key of the signer
            - blinded_message: A blinded message to be signed
        Outputs:
            - sigma_dash: Signature on the blinded message
        """
        print("This is a stub function. Implement it in the child class")

    def unblind(self, blinded_sig, t):
        """
        This function takes a blinded signature and returns the unblinded signature
        Inputs:
            - blinded_sig: Blinded signature
            - t: random number used to blind the original message
        Outputs:
            - sigma: unblinded signature
        """
        print("This is a stub function. Implement it in the child class")

    def verify(self, message, pk, sig) -> bool:
        """
        This function is used for the user to verify a signature on a specific message using the message and the public
        key of the signer.
        Inputs:
            - message: The message
            - pk: Public key
            - sig: signature
        Outputs:
            - True if the signature is valid on the message by the user whose public key is pk
            - False, otherwise
        """
        print("This is a stub function. Implement it in the child class")


class PS_BlindSingleMessageSig(PS_BlindSig):

    def __init__(self, groupObj):
        PS_BlindSig.__init__(self, groupObj)

    def keygen(self):
        """
        This function is used to generate the secret key and the public key of the signer
        Outputs:
            - sk: Secret key
            - pk: public key
        """
        g = self.group.random(G1)
        g_tilde = self.group.random(G2)
        x = self.group.random()
        y = self.group.random()

        X = g ** x
        Y = g ** y
        X_tilde = g_tilde ** x
        Y_tilde = g_tilde ** y

        pk = {'g': g, 'Y': Y, 'g_tilde': g_tilde, 'X_tilde': X_tilde, 'Y_tilde': Y_tilde}
        sk = {'X': X}

        return sk, pk

    def blind(self, message, pk):
        """
        This function takes a message and blinds it to return a blinded message.
        Inputs:
            - message: message to be blinded
            - pk: pk is needed to know some of the public parameters used in message blinding
        Outputs:
            - C: A blinded message
            - t: Blind random value
        """
        m = self._dump_to_zp_element(message)  # serialize the message to an element
        t = self.group.random()
        C = (pk['g'] ** t) * (pk['Y'] ** m)

        return C, t

    def sign(self, sk, pk, blinded_message):
        """
        This function is used for the signer to sign a message
        Inputs:
            - sk: Secret key of the signer
            - pk: Public key of the signer
            - blinded_message: A blinded message to be signed
        Outputs:
            - sigma_dash: Signature on the blinded message
        """
        C = blinded_message
        u = self.group.random()
        sigma_dash_1 = pk['g'] ** u
        sigma_dash_2 = (sk['X'] * C) ** u
        sigma_dash = (sigma_dash_1, sigma_dash_2)

        return sigma_dash

    def unblind(self, blinded_sig, t):
        """
        This function takes a blinded signature and returns the unblinded signature
        Inputs:
            - blinded_sig: Blinded signature
            - t: random number used to blind the original message
        Outputs:
            - sigma: unblinded signature
        """
        sigma_dash_1, sigma_dash_2 = blinded_sig
        sigma_1 = sigma_dash_1
        sigma_2 = sigma_dash_2 / (sigma_dash_1 ** t)

        sigma = (sigma_1, sigma_2)
        return sigma

    def verify(self, message, pk, sig) -> bool:
        """
        This function is used for the user to verify a signature on a specific message using the message and the public
        key of the signer.
        Inputs:
            - message: The message
            - pk: Public key
            - sig: signature
        Outputs:
            - True if the signature is valid on the message by the user whose public key is pk
            - False, otherwise
        """
        sigma_1, sigma_2 = sig
        m = self._dump_to_zp_element(message)  # serialize the message to an element
        if pair(sigma_1, pk['X_tilde'] * (pk['Y_tilde'] ** m)) == pair(sigma_2, pk['g_tilde']):
            return True
        return False


class PS_SigSingleMessage(PS_Sig):

    def __init__(self, groupObj):
        PS_Sig.__init__(self, groupObj)

    def keygen(self):
        """
        This function is used to generate the secret key and the public key of the signer
        """
        g_tilde = self.group.random(G2)
        x = self.group.random()
        y = self.group.random()
        X_tilde = g_tilde ** x
        Y_tilde = g_tilde ** y

        pk = {'g_tilde': g_tilde, 'X_tilde': X_tilde, 'Y_tilde': Y_tilde}
        sk = {'x': x, 'y': y}

        return sk, pk

    def sign(self, sk, message):
        """
        This function is used for the signer to sign a message
        Inputs:
            - sk: Secret key of the signer
            - message: message to be signed
        Outputs:
            - sigma: Signature on the message
        """
        m = self._dump_to_zp_element(message) # serialize the message to an element
        h = self.group.random(G1)
        sigma = (h, h ** (sk['x'] + sk['y'] * m))

        return sigma

    def verify(self, message, pk, sig) -> bool:
        """
        This function is used for the user to verify a signature on a specific message using the message and the public
        key of the signer.
        Inputs:
            - message: The message
            - pk: Public key
            - sig: signature
        Outputs:
            - True if the signature is valid on the message by the user whose public key is pk
            - False, otherwise
        """
        sigma_1, sigma_2 = sig
        m = self._dump_to_zp_element(message)  # serialize the message to an element
        if pair(sigma_1, pk['X_tilde'] * (pk['Y_tilde'] ** m)) == pair(sigma_2, pk['g_tilde']):
            return True
        return False


def single_message_main(debug=False):
    message = "Welcome to PS signature scheme"
    group_obj = PairingGroup('MNT224')
    ps_sig = PS_SigSingleMessage(group_obj)

    sk, pk = ps_sig.keygen()
    if debug:
        print("sk = ", sk)
        print("pk = ", pk)

    sigma = ps_sig.sign(sk, message)
    if debug:
        print("signature: ", sigma)
    verification_res = ps_sig.verify(message, pk, sigma)
    if verification_res:
        print("Verification is successful")
    else:
        print("Error! This signature is not valid on this message")


def blinded_single_message_main(debug=False):
    message = "Welcome to PS signature scheme"
    group_obj = PairingGroup('MNT224')
    ps_sig = PS_BlindSingleMessageSig(group_obj)

    sk, pk = ps_sig.keygen()
    if debug:
        print("sk = ", sk)
        print("pk = ", pk)

    blinded_message, t = ps_sig.blind(message, pk)
    if debug:
        print("Blinded Message: ", blinded_message)
    # TODO: AB: The user should send here a proof of knowledge of the original message and the value t before the signer signs the message

    blinded_signature = ps_sig.sign(sk, pk, blinded_message)
    if debug:
        print("Blinded signature: ", blinded_signature)

    signature = ps_sig.unblind(blinded_signature, t)
    if debug:
        print("Signature: ", signature)
    verification_res = ps_sig.verify(message, pk, signature)
    if verification_res:
        print("Verification is successful")
    else:
        print("Error! This signature is not valid on this message")


if __name__ == "__main__":
    debug = True
    # single_message_main(debug)
    blinded_single_message_main(debug)
    print("done")
