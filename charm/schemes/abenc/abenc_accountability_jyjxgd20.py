'''
Jiguo Li, Yichen Zhang, Jianting Ning, Xinyi Huang, Geong Sen Poh, Debang Wang (Pairing-based)

| From: "Attribute Based Encryption with Privacy Protection and Accountability for CloudIoT".
| Published in: 2020
| Available from: https://ieeexplore.ieee.org/abstract/document/9003205
| Notes:
| Security Assumption:
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing
|
| Authors:        Ahmed Bakr
| Date:           07/2023
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output

from typing import Dict, List, Tuple
import queue


class Attribute:
    def __init__(self, attr_name, values_list: List[str] = []):
        # Validation
        self.__validate_attribute_values_name(attr_name)
        for value_str in values_list:
            self.__validate_attribute_values_name(value_str)

        self.name = attr_name
        self.values = values_list

    def __validate_attribute_values_name(self, attr_value_name: str):
        assert attr_value_name.find('_') == -1, "Attribute name cannot contain an '_'"

    def add_value(self, value: str):
        self.__validate_attribute_values_name(value)  # Validation
        self.values.append(value)

    def set_values(self, values_list: List[str]):
        self.values = values_list


class CP_Hiding_ABE:
    """
    Cipher text policy hiding attribute based encryption (Section 3 in the paper).
    """
    def __init__(self):
        pass

    def setup(self):
        """
        System Setup algorithm. This algorithm is performed by TA.
        Inputs:
            - None
        Outputs:
            - MSK: TA's master secret key.
            - PK: Public Parameters.
        """
        pass

    def key_gen(self, MSK, PK, attributes_list):
        """
        Key generation for a user based on his list of attributes. This algorithm is performed by TA.
        Inputs:
            - MSK: Master Secret Key of the TA.
            - PK: Public parameters and the public key of the TA.
            - attributes_list: List of attributes held by this user.
        Outputs:
            - SK: User's secret key.
        """
        pass

    def encrypt(self, m, PK, access_policy):
        """
        Encrypt a message using an access policy. This function is performed by a data user who wants to encrypt his 
        message with an access policy.
        Note: The access policy is hidden into the ciphertext.
        Inputs:
            - PK: Public parameters and the public key of the TA.
            - m: Message to be encrypted.
            - access_policy: Access policy that will be used to encrypt the message.
        Outputs:
            - CT: Cipher text. 
        """
        pass
    
    def decrypt(self, CT, PK, SK):
        """
        Decrypt a cipher text. This algorithm is performed by a data user who has the required attributes to decipher
        the ciphertext that was encrypted using an access policy.
        Inputs:
            - MSK: Master Secret Key of the TA.
            - PK: Public parameters and the public key of the TA.
            - attributes_list: List of attributes held by this user.
        Outputs:
            - m: The original decrypted message.
        """
        pass
