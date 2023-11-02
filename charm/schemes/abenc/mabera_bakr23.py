'''
Ahmed Bakr, Ahmad Alsharif, Mahmoud Nabil (Pairing-based)

| From: "TBD".
| Published in: 2024
| Available from: TBD
| Notes:
| Security Assumption:
|
| type:           multi-authority-ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing
|
| Authors:        Ahmed Bakr
| Date:           09/2023
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,hashPair
# from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from typing import Dict, List, Tuple
import queue
import re
from hashlib import sha256

# type annotations
mk_t = {'beta':ZR, 'g_alpha':G1 }
pp_t = { 'g':G1, 'g_beta':G1, 'g_1_over_beta':G1, 'e_gg_alpha':GT }


class TreeNode:
    def __init__(self, sequence_number, value, parent=None):
        self.parent = parent
        self.sequence_number = sequence_number
        self.value = value
        self.left = None
        self.right = None

    def __str__(self):
        return str(self.sequence_number)

    def __repr__(self):
        return self.__str__()


class UsersBinaryTree:
    """
    A binary tree that is used to assign users to leafs in a deterministic way.
    The tree is created and maintained by the AM.
    """
    def __init__(self, group_obj):
        self.group = group_obj
        self.leafs_queue = queue.Queue()
        self.sequence_number = 0
        self.root = self.create_node()
        self.leafs_queue.put(self.root)
        self.__curr_node = self.leafs_queue.get()

    def create_node(self) -> TreeNode:
        self.sequence_number += 1
        return TreeNode(self.sequence_number, self.group.random(ZR))

    def add_node_to_tree(self, tree_node: TreeNode):
        """
        Add a node to the tree.
        Inputs:
            - tree_node: a node to be added to the tree
        """
        if self.__curr_node.left and self.__curr_node.right:
            assert not self.leafs_queue.empty(), "Leafs queue is empty and pull attempts was made"
            self.__curr_node = self.leafs_queue.get()
        if not self.__curr_node.left:
            self.__curr_node.left = tree_node
        elif not self.__curr_node.right:
            self.__curr_node.right = tree_node
        else:
            assert True, "This statement should not be reached"
        tree_node.parent = self.__curr_node
        self.leafs_queue.put(tree_node)

    def print_tree(self):
        print("{", end='')
        self.__print_tree_rec(self.root)
        print("}")

    def __print_tree_rec(self, node: TreeNode):
        print(node, end=', ')
        if node.left:
            self.__print_tree_rec(node.left)
        if node.right:
            self.__print_tree_rec(node.right)


class AM:
    """Attribute Manager (AM)"""
    def __init__(self, am_cfg, group_obj):
        self.am_cfg = am_cfg
        self.users_to_attrs_dict: Dict[str, list] = {}
        self.attrs_to_users_dict: Dict[str, list] = {}
        self.users_init_kek_dict = {}  # The key of the dictionary is the username and the value is the initial kek
        # generated for this user by the attribute-issuer.

        self.users_binary_tree = UsersBinaryTree(group_obj)

    def add_attr_to_user(self, attr_str: str, user_name: str):
        if user_name not in self.users_to_attrs_dict:
            self.users_to_attrs_dict[user_name] = []
            self.__create_node_in_binary_tree_for_new_user()

        if attr_str not in self.attrs_to_users_dict:
            self.attrs_to_users_dict[attr_str] = []

        self.users_to_attrs_dict[user_name].append(attr_str)  # AB: It is assumed that this attribute does not already
        # exist in the list
        self.attrs_to_users_dict[attr_str].append(user_name)  # AB: It is assumed that the username does not already
        # exist in the list

    def __create_node_in_binary_tree_for_new_user(self):
        current_number_of_users = len(list(self.users_to_attrs_dict.keys()))  # AB: make sure to add the new user to the
        # dict first before calling this function
        while not current_number_of_users == self.users_binary_tree.leafs_queue.qsize():
            new_node = self.users_binary_tree.create_node()
            self.users_binary_tree.add_node_to_tree(new_node)

    def remove_attr_from_user(self, attr_str: str, user_name: str):
        index = self.attrs_to_users_dict[attr_str].index(user_name)
        self.attrs_to_users_dict[attr_str].pop(index)

        index = self.users_to_attrs_dict[user_name].index(attr_str)
        self.users_to_attrs_dict[user_name].pop(index)

    def get_user_assignation_to_leafs_dict(self) -> Dict[str, TreeNode]:
        user_names_list = list(self.users_to_attrs_dict.keys())
        assert len(user_names_list) == self.users_binary_tree.leafs_queue.qsize(), "The number of usernames list ({})" \
                                                                                " has to match the number of leaf" \
                                                                                " elements ({}) in the binary tree".format(
            len(user_names_list), self.users_binary_tree.leafs_queue.qsize())
        ret_dict: Dict[str, TreeNode] = {}
        for user_name, leaf in zip(user_names_list, self.users_binary_tree.leafs_queue.queue):
            ret_dict[user_name] = leaf

        return ret_dict

    def get_minimum_nodes_list_that_represent_users_list(self, user_names_list: List[str]) -> List[TreeNode]:
        """
        This is represented in the paper as calculating node(Gi)
        """
        visited_arr = [False] * (self.users_binary_tree.sequence_number + 1)
        list_of_leaves_to_traverse = []

        user_assignation_to_leafs_dict = self.get_user_assignation_to_leafs_dict()
        for user_name in user_names_list:
            user_leaf_node = user_assignation_to_leafs_dict[user_name]
            visited_arr[user_leaf_node.sequence_number] = True
            list_of_leaves_to_traverse.append(user_leaf_node)

        self.__traverse_to_mark_all_children_visited_arr(self.users_binary_tree.root, visited_arr)

        return self.__traverse_bfs_to_get_minimum_number_nodes_to_cover_users_list(visited_arr)

    def __traverse_to_mark_all_children_visited_arr(self, node: TreeNode, visited_arr: List[bool]):
        is_leaf = not node.left and not node.right
        if is_leaf:
            return
        if node.left:
            self.__traverse_to_mark_all_children_visited_arr(node.left, visited_arr)
        if node.right:
            self.__traverse_to_mark_all_children_visited_arr(node.right, visited_arr)

        visited_arr[node.sequence_number] = (not node.left or visited_arr[node.left.sequence_number]) and (not node.right or visited_arr[
            node.right.sequence_number])

    def __traverse_bfs_to_get_minimum_number_nodes_to_cover_users_list(self, visited_arr) -> List[TreeNode]:
        ret_list = []
        q = queue.Queue()
        q.put(self.users_binary_tree.root)

        while not q.empty():
            node: TreeNode = q.get()
            if visited_arr[node.sequence_number]:
                ret_list.append(node)
            else:
                if node.left:
                    q.put(node.left)
                if node.right:
                    q.put(node.right)

        return ret_list

    def get_user_path(self, user_name) -> List[TreeNode]:
        ret_list = []
        user_assignation_to_leafs_dict = self.get_user_assignation_to_leafs_dict()
        assert user_name in user_assignation_to_leafs_dict, \
            "Username ({}) must be inside user_assignation_to_leafs_dict ({})".format(user_name,
                                                                                      user_assignation_to_leafs_dict)
        user_leaf_node = user_assignation_to_leafs_dict[user_name]
        curr_node: TreeNode = user_leaf_node
        while curr_node:
            ret_list.append(curr_node)
            curr_node = curr_node.parent

        return ret_list

    @staticmethod
    def get_user_path_intersection_with_node_gi(user_path: List[TreeNode], node_gi: List[TreeNode]) -> List[TreeNode]:
        ret_intersection_list = []
        for user_node in user_path:
            if user_node in node_gi:
                ret_intersection_list.append(user_node)

        return ret_intersection_list


class ShnorrInteractiveZKP():
    """
    Shnorr's Interactive ZKP
    """
    class Prover:
        def __init__(self, secret_x, groupObj):
            self.__r = None
            self.group = groupObj
            self.__x = secret_x

        def create_prover_commitments(self, pk):
            """
            1) This function is executed by the prover to send a random value to the verifier
            """
            self.__r = self.group.random()
            u = (pk['g'] ** self.__r)
            return u

        def create_proof(self, c):
            """
            3) This function is executed by the prover after he received the challenge value (c) from the verifier
            """
            z = self.__r + c * self.__x
            return z  # proof

    class Verifier:

        def __init__(self, groupObj):
            self.group = groupObj

        def create_verifier_challenge(self):
            """
            2) This function is executed by the verifier after he had received the value u from the prover to send a challenge value to the prover.
            """
            self.c = self.group.random()
            return self.c

        def is_proof_verified(self, z, pk, u, h):
            """
            4) This function is executed by the verifier to verify the authenticity of the proof sent by the prover
            z: Created by the prover in create_proof function
            u: Created by the prover in create_prover_commitments function
            h: g^x, where x is the secret key of the prover that he wants to prove that he knows it.
            """
            if (pk['g'] ** z) == u * h ** self.c:
                return True
            return False


class MABERA(ABEncMultiAuth):
    def __init__(self, group_obj):
        ABEncMultiAuth.__init__(self)
        self.util = SecretUtil(group_obj, verbose=False)
        self.group = group_obj
        
    def system_setup(self):
        """
        System Setup algorithm. (One time to agree on the parameters).
        Inputs:
            - None
        Outputs:
            - PP: Public Parameters.
        """
        g = self.group.random(G1)
        e_gg = pair(g, g)
        PP = {'g': g,
              'e_gg': e_gg}
        return PP
        
    def authority_setup(self, name: str, PP: dict):
        """
        Authority Setup algorithm. Executed by the authority issuing a specific set of attributes.
        Inputs:
            - name: Attribute authority name.
            - PP: Public Parameters.
        Outputs:
            - PK_theta: Public key for authority (theta).
            - SK_theta: Secret key for authority (theta).
        """
        alpha_theta, beta_theta = self.group.random(ZR), self.group.random(ZR)
        g = PP['g']
        e_gg_alpha_theta = pair(g, g) ** alpha_theta
        g_beta_theta = g ** beta_theta

        PK_theta = {'name': name,
                    'e_gg_alpha_theta': e_gg_alpha_theta,
                    'g_beta_theta': g_beta_theta}
        SK_theta = {'alpha_theta': alpha_theta,
                    'beta_theta': beta_theta}
        
        return PK_theta, SK_theta

    def manager_setup(self, attribute_names: List[str], PP):
        """
        Manager Setup algorithm performed by AM.
        Inputs:
            - attribute_names: The name of attributes that AM is responsible for.
            - PP: Public Parameters from the system setup algorithm.
        Outputs:
            - MMK_m: Manager (m) master key represented as a dictionary.
            - MPK_m: Manager (m) public key represented as a dictionary.
        """
        MMK_m = {}
        MPK_m = {}
        for attr in attribute_names:
            t_m_u = self.group.random(ZR)
            g = PP['g']
            T_m_u = g ** t_m_u
            MMK_m[attr] = t_m_u
            MPK_m[attr] = T_m_u

        return MMK_m, MPK_m

    def attribute_key_gen(self, attribute_names: List[str], SK_theta, UID, MPK_m, PP, g_gamma, gamma_i):
        """
        The attribute issuer (AI) executes this function to issue the decryption key used by the user.
        This function is executed by both the user and the attribute authority interactively.
        Inputs:
            - attribute_names: The name of attributes that the attribute authority is issuing for the user.
            - SK_theta: Secret key of the attribute issuer (theta).
            - UID: User_i ID.
            - MPK_m: Attribute Manager (m) public key.
            - PP: Public Parameters from the system setup algorithm.
            - g_gamma: g ** gamma_i, where gamma_i is the secret value chosen by the user and kept secretly by him.
            - gamma_i: The secret value chosen by the user and kept secretly by him.
        Outputs:
            - DSK_i: Decryption secret key for user_i
            - kek_dict: KEK initial key, which is given to AM_m.
        """
        g = PP['g']
        # Interactive ZKP by both the user and the AI, where the user proves knowledge of (gamma_i).
        self.__attribute_key_gen_interactive_ZKP(PP, g_gamma, gamma_i)

        DSK_i, kek_dict = self.__attribute_key_gen_by_AI(MPK_m, SK_theta, UID, attribute_names, g, g_gamma)

        return DSK_i, kek_dict

    def __attribute_key_gen_by_AI(self, MPK_m, SK_theta, UID, attribute_names, g, g_gamma):
        """
        The attribute issuer (AI) executes this function to issue the decryption key used by the user.
        Inputs:
            - MPK_m: Attribute Manager (m) public key.
            - SK_theta: Secret key of the attribute issuer (theta).
            - UID: User_i ID.
            - attribute_names: The name of attributes that the attribute authority is issuing for the user.
            - gamma_i: The secret value chosen by the user and kept secretly by him.
            - g_gamma: g ** gamma_i, where gamma_i is the secret value chosen by the user and kept secretly by him.
        Outputs:
            - DSK_i_theta: Decryption secret key for user_i issued by authority theta
            - kek_dict: KEK initial key, which is given to AM_m.
        """
        alpha_theta = SK_theta['alpha_theta']
        beta_theta = SK_theta['beta_theta']
        kek_dict = {}
        D_i_theta_u_dict = {}
        D_i_theta_u_dash_dict = {}
        for attr_name in attribute_names:
            r_i_u = self.group.random(ZR)
            D_i_theta_u = ((g ** alpha_theta) * (self.group.hash(UID, G1) ** beta_theta) *
                   (self.group.hash(attr_name, G1) ** (r_i_u)))
            D_i_theta_u_dash = g_gamma ** (r_i_u)
            kek_theta_u = MPK_m[attr_name] ** r_i_u
            kek_dict[attr_name] = kek_theta_u
            D_i_theta_u_dict[attr_name] = D_i_theta_u
            D_i_theta_u_dash_dict[attr_name] = D_i_theta_u_dash
        DSK_i_theta = {'D_u_dict': D_i_theta_u_dict, 'D_u_dash_dict': D_i_theta_u_dash_dict}

        return DSK_i_theta, kek_dict

    def __attribute_key_gen_interactive_ZKP(self, PP, g_gamma, gamma_i):
        # ZKP interactive Protocol between the user and AI.
        zkp_prover = ShnorrInteractiveZKP.Prover(gamma_i, self.group)  # The user.
        zkp_verifier = ShnorrInteractiveZKP.Verifier(self.group)  # The AI.
        u = zkp_prover.create_prover_commitments(PP)
        c = zkp_verifier.create_verifier_challenge()
        z = zkp_prover.create_proof(c)
        assert zkp_verifier.is_proof_verified(z, PP, u, g_gamma), \
            "User failed to proof knowledge of (g) that is used to calculate g_gamma"

    def attribute_key_gen_user_part(self, g):
        # User choose a secret value (gamma_i) and shared g ** gamma_i with AI. Then proves a proof of knowledge of gamma_i
        # using interactive ZKP.
        gamma_i = self.group.random(ZR)
        g_gamma = g ** gamma_i
        return g_gamma, gamma_i

    def user_attributes_kek_generation(self, init_kek, attributes_manager, user_attribute_names_list, user_name):
        """
        This function is executed by AM and considered as part of key generation procedure.
        Inputs:
            - init_kek: Preliminary KEK list generated by AI.
            - attributes_manager: AM.
            - user_attribute_names_list: Attribute names hold by the user.
            - user_name: User name.
        Outputs:
            - KEK_i: Key Encryption Keys generated for each attribute hold by the user using the users binary tree
              generated by AM.
        """
        KEK_i = {}
        for attr in user_attribute_names_list:
            if user_name not in attributes_manager.users_init_kek_dict:
                attributes_manager.users_init_kek_dict[user_name] = {}
            attributes_manager.users_init_kek_dict[user_name].update(init_kek)
            KEK_attr = self.__generate_kek_for_user_with_attr(init_kek, attr, attributes_manager, user_name)
            KEK_i[attr] = KEK_attr
        return KEK_i

    def __generate_kek_for_user_with_attr(self, init_kek, attr, attributes_manager, user_name):
        """
        This function is executed by AM and considered as part of key generation procedure.
        Inputs:
            - init_kek: Preliminary KEK list generated by AI.
            - attributes_manager: AM.
            - user_attribute_names_list: Attribute names hold by the user.
            - user_name: User name.
        Outputs:
            - KEK_i_theta_u_dict: Key Encryption Key generated for a specific attribute hold by the user using
                                  the users binary tree generated by AM.
        """
        list_of_users_hold_attr = attributes_manager.attrs_to_users_dict[attr]
        node_G_m_u = attributes_manager.get_minimum_nodes_list_that_represent_users_list(list_of_users_hold_attr)
        user_path = attributes_manager.get_user_path(user_name)
        intersection = attributes_manager.get_user_path_intersection_with_node_gi(user_path, node_G_m_u)
        if len(intersection) == 0:
            # AB: Do nothing, as mentioned in the paper.
            return None
        else:
            assert len(intersection) == 1, "The intersection list should have only one element."
            v_y_node: TreeNode = intersection[0]
            kek_i_theta_u = init_kek[attr]
            # Consider fixing it later if this functionality is needed.
            KEK_i_theta_u = kek_i_theta_u ** (1 / v_y_node.value)
            KEK_i_theta_u_dict = {'seq(v_y)': v_y_node.sequence_number, 'kek_u': kek_i_theta_u, 'KEK_u': KEK_i_theta_u}
            return KEK_i_theta_u_dict

    def local_encryption(self, A, M, PKs, PP, header_regeneration_enabled=True):
        """
        This function is executed by anyone who wants to encrypt a message with an access policy.
        Inputs:
            - A: Access policy represented as a boolean expression string.
            - M: Message to by encrypted.
            - PKs: The public keys of the relevant attribute authorities, as dict from authority name to public key.
            - PP: Public Parameters from the system setup algorithm.
        Outputs:
            - CT: Ciphertext.
            - K_dash: Given to each AM for the header generation process.
            - a_xs_dict: The random a_x values used in the encryption because the encryptor will use them later to re-encrypt the headers generated by AMs.
        """
        s = self.group.random(ZR)  # secret to be shared
        w = self.group.init(ZR, 0)  # 0 to be shared

        policy = self.util.createPolicy(A)
        attribute_list = self.util.getAttributeList(policy)

        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.util.calculateSharesDict(w, policy)
        e_gg = PP['e_gg']
        C0 = M * (e_gg ** s)
        C1, C2, C3, C4 = {}, {}, {}, {}
        K_dash = {}
        a_xs_dict = {}
        for u in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(u)
            attr_full_name = "%s@%s" % (attribute_name, auth)
            rx = self.group.random()
            kx = self.group.random()
            if header_regeneration_enabled:
                ax = self.group.random()
                a_xs_dict[attr_full_name] = ax
            g_kx = PP['g'] ** kx
            C1[u] = (PP['e_gg'] ** secret_shares[u]) * (PKs[auth]['e_gg_alpha_theta'] ** rx)
            C2[u] = PP['g'] ** (-rx)
            C3[u] = PKs[auth]['g_beta_theta'] ** rx * PP['g'] ** zero_shares[u]
            C4[u] = (self.group.hash(attr_full_name, G1) ** rx) * (g_kx ** ax) if header_regeneration_enabled else (self.group.hash(attr_full_name, G1) ** rx)
            K_dash[u] = g_kx
            CT = {'policy': A, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}
        return CT, K_dash, a_xs_dict

    def unpack_attribute(self, attribute):
        """
        Unpacks an attribute in attribute name, authority name and index
        :param attribute: The attribute to unpack
        :return: The attribute name, authority name and the attribute index, if present.

        >>> group = PairingGroup('SS512')
        >>> maabe = MaabeRW15(group)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def generate_ciphertext_headers(self, K_dash, MMK_m, attributes_manager, a_xs_dict, PP: dict, header_regeneration_enabled=True):
        """
        This function is mainly performed by the AM and it is the second part of the encryption procedure.
        After the AM generates the headers for the encrypted message, it sends them to the encryptor for him to add the
        final part on those headers.
        Inputs:
            - K_dash: Given to each AM for the header generation process. It is generated as part of the
                      local_encryption function.
            - MMK_m: Manager (m) master key represented as a dictionary.
            - attributes_manager: AM.
        Outputs:
            - Hdr_m_dict: The header for the encrypted message.
        """
        Hdr_m_dict = self.generate_ciphertext_headers_by_AM(K_dash, MMK_m, attributes_manager, PP)
        if header_regeneration_enabled:
            # This function is executed by the encryptor. First, The encryptor verifies that the AM calculated the proof
            # correctly. Then, it changes internally the Hdr_m_dict for the decryptor to be able to decrypt.
            self.regenerate_headers_by_encryptor(Hdr_m_dict, a_xs_dict, PP)

        return Hdr_m_dict

    def generate_ciphertext_headers_by_AM(self, K_dash, MMK_m, attributes_manager, PP: dict, zkp_enabled=True):
        """
        This function is performed by the AM and it is the second part of the encryption procedure.
        Inputs:
            - K_dash: Given to each AM for the header generation process. It is generated as part of the
                      local_encryption function.
            - MMK_m: Manager (m) master key represented as a dictionary.
            - attributes_manager: AM.
            - PP: Public Parameters.
        Outputs:
            - Hdr_m_dict: The header for the encrypted message.
        """
        Hdr_m_dict = {}
        for attr_name_with_idx in K_dash:
            attr_name_without_idx = self.__get_attr_name_without_idx(attr_name_with_idx)
            if not attr_name_without_idx in attributes_manager.attrs_to_users_dict:
                # Attribute manager is not responsible for this attribute
                # AB: TODO: Attention here. You might need to revisit this part.
                continue
            G_theta_u = attributes_manager.attrs_to_users_dict[attr_name_without_idx]
            node_G_theta_u = attributes_manager.get_minimum_nodes_list_that_represent_users_list(G_theta_u)
            if not attr_name_with_idx in Hdr_m_dict:
                Hdr_m_dict[attr_name_with_idx] = []
            for a_node_G_theta_u in node_G_theta_u:
                a_node_G_theta_u: TreeNode = a_node_G_theta_u
                E_k_x_v_y = K_dash[attr_name_without_idx] ** (a_node_G_theta_u.value / MMK_m[attr_name_without_idx])
                # AM Generates the proof.
                if zkp_enabled:
                    pi_v_y_and_t_m_u = self.__generate_proof_of_correct_header(a_node_G_theta_u.value,
                                                                           MMK_m[attr_name_without_idx], E_k_x_v_y,
                                                                           K_dash[attr_name_without_idx], PP)
                else:
                    pi_v_y_and_t_m_u = None
                Hdr_m_dict[attr_name_with_idx].append({'seq': a_node_G_theta_u.sequence_number, 'E(k_x,v_y)': E_k_x_v_y,
                                                       'proof': pi_v_y_and_t_m_u})

        return Hdr_m_dict

    def regenerate_headers_by_encryptor(self, Hdr_m_dict, a_xs_dict, PP, zkp_enabled=True):
        """
        This function is executed by the encryptor to regererate the final headers after he gets the preliminary ones from the AMs.
        Inputs:
            - Hdr_m_dict: Headers dictionary generated by the AM.
            - a_xs_dict: Private random values chosen by the encryptor when local_encryption function is executed.
            - PP: Public generic parameters.
        Outputs:
            - It changes the value of the dictionary value 'E(k_x, v_y)' inside Hdr_m_dict.
        """
        # The encryptor adds the final part to the header to be used by the decryptors.
        for an_attr in Hdr_m_dict.keys():
            for index, _ in enumerate(Hdr_m_dict[an_attr]):
                hdr_m_y = Hdr_m_dict[an_attr][index]
                if zkp_enabled:
                    pi_v_y_and_t_m_u = hdr_m_y['proof']
                    self.__verify_correct_header_proof(pi_v_y_and_t_m_u, PP)
                E_k_x_v_y = hdr_m_y['E(k_x,v_y)']
                E_dash_k_x_v_y = E_k_x_v_y ** a_xs_dict[an_attr]
                Hdr_m_dict[an_attr][index]['E(k_x,v_y)'] = E_dash_k_x_v_y
    
    def __generate_proof_of_correct_header(self, v_y, MMK_m_u, E_k_x_v_y, K_dash_u, PP):
        """
        In this function, the AM proves that he have correctly calculated the header using Fiat-Shamir non-interactive
        protocol.
        """
        global R_v_y, R_t_m_u, R_E_k_x_v_y # AB: TODO: To be removed.
        g = PP['g']
        V_y, one_over_T_m_u, VT = g ** v_y, g ** (1/MMK_m_u), g**(v_y/MMK_m_u)
        r_v_y, r_t_m_u, r_v_t = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        R_v_y, R_t_m_u, R_v_t = g ** r_v_y, g ** r_t_m_u, g** r_v_t
        R_E_k_x_v_y = K_dash_u ** (r_v_t) # AB: It is multiplication not division because r_t_m_u represents (1/t_m_u)
        challenge = self.calculate_hash_of_EC_points(E_k_x_v_y, K_dash_u, V_y, one_over_T_m_u, R_v_y, R_t_m_u, R_v_t, R_E_k_x_v_y)
        s_v_y, s_t_m_u, s_v_t = r_v_y + challenge * v_y, r_t_m_u + challenge * (1/MMK_m_u), r_v_t + challenge * (v_y/MMK_m_u)
        pi_v_y_and_t_m_u = (E_k_x_v_y, K_dash_u, V_y, one_over_T_m_u, VT, s_v_y, s_t_m_u, s_v_t, challenge)
        return pi_v_y_and_t_m_u

    def __verify_correct_header_proof(self, pi_v_y_and_t_m_u, PP):
        """
        This function is executed by the encryptor to make sure that the AM has successfully computed the header.
        """
        global R_v_y, R_t_m_u, R_E_k_x_v_y  # AB: TODO: To be removed.
        g = PP['g']
        (E_k_x_v_y, K_dash_u, V_y, one_over_T_m_u, VT, s_v_y, s_t_m_u, s_v_t, challenge) = pi_v_y_and_t_m_u
        R_dash_v_y = (g ** s_v_y) * V_y ** (-challenge)
        R_dash_t_m_u = (g ** s_t_m_u) * one_over_T_m_u ** (-challenge)
        R_dash_v_t = (g ** s_v_t) * VT ** (-challenge)
        R_dash_E_k_x_v_y = K_dash_u ** (s_v_t) * E_k_x_v_y ** (-challenge) # AB: s_t_m_u represents (1/t_m_u)
        challenge_dash = self.calculate_hash_of_EC_points(E_k_x_v_y, K_dash_u, V_y, one_over_T_m_u,
                                                          R_dash_v_y, R_dash_t_m_u, R_dash_v_t, R_dash_E_k_x_v_y)
        assert challenge_dash == challenge, \
            "User failed to proof knowledge of (g) that is used to calculate g_gamma"


    def calculate_hash_of_EC_points(self, *points_list):
        accum = ""
        for a_point in points_list:
            accum += hashPair(a_point).decode('utf-8')
        accum = bytes(bytearray.fromhex(accum))
        hash_val = int.from_bytes(sha256(accum).digest(), byteorder='big')
        return self.group.init(ZR, hash_val)

    def __get_attr_name_without_idx(self, attr_name: str):
        if attr_name.find('_') == -1:
            return attr_name
        val = attr_name.split('_')
        return val[0]

    def decrypt(self, PP, CT, Hdr, user_secret_keys, UID, user_name: str, attributes_manager: AM):
        """
        This function is used by any user who has sufficient, non revoked attributes to decrypted a message under a
        specific access policy.
        Inputs:
            - PP: Public Parameters from the system setup algorithm.
            - CT_tilde: Ciphertext after re-encryption by the AM.
            - Hdr: Header message.
            - user_secret_keys: Contains user secret keys DSK (from AI), KEK (from AM), gamma_i (Privately preserved value)
            - UID: User ID.
            - user_name: Username who is decrypting the ciphertext.
            - attributes_manager: AM.
        Outputs:
            - M: Recovered message, if the user has the decryption keys of the attributes that satisfy the policy.
        """
        DSK_i = user_secret_keys['DSK_i']
        KEK_i = user_secret_keys['KEK_i']
        gamma_i = user_secret_keys['gamma_i']
        policy = self.util.createPolicy(CT['policy'])
        coefficients = self.util.getCoefficients(policy)
        pruned_list = self.util.prune(policy, DSK_i['D_u_dict'].keys())
        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        B = self.group.init(GT, 1)

        for attr_node in pruned_list:
            attr_name_with_idx = attr_node.getAttributeAndIndex()
            attr_name_without_idx = attr_node.getAttribute()
            KEK_i_u = KEK_i[attr_name_without_idx]['KEK_u']
            Hdr_for_attr: list = Hdr[attr_name_with_idx]
            chosen_Hdr_element = None
            user_path = attributes_manager.get_user_path(user_name)
            for hdr_elem in Hdr_for_attr:
                # If hdr_ele intersect with the user path, then it is the chosen element
                found = False
                for user_node in user_path:
                    if user_node.sequence_number == hdr_elem['seq']:
                        found = True
                if found:
                    chosen_Hdr_element = hdr_elem
            E_k_x_v_y = chosen_Hdr_element['E(k_x,v_y)']
            C1_x = CT['C1'][attr_name_with_idx]
            C2_x = CT['C2'][attr_name_with_idx]
            C3_x = CT['C3'][attr_name_with_idx]
            C4_x = CT['C4'][attr_name_with_idx]
            D_x = DSK_i['D_u_dict'][attr_name_without_idx]
            D_dash_x = DSK_i['D_u_dash_dict'][attr_name_without_idx]
            nominator = ((C1_x ** gamma_i) * pair(D_x, C2_x ** gamma_i) * pair(self.group.hash(UID, G1) ** gamma_i, C3_x)
                         * pair(D_dash_x, C4_x)) ** (1 / gamma_i)
            denominator = pair(KEK_i_u, E_k_x_v_y)
            B *= (nominator / denominator) ** coefficients[attr_name_with_idx]

        return CT['C0'] / B

    def revoke_attribute(self, revoked_user_name, attribute_name, attributes_manager: AM):
        """
        This function is executed by AM when an attribute is revoked from a user.
        Inputs:
            - revoked_user_name: The name of the revoked user.
            - attribute_name: revoked attribute name.
            - attributes_manager: AM.
        Outputs:
            - updated_KEK_dict: The key is the user-name of the user whose KEK key is updated and the value is the
                                updated KEK key value.
        """
        attributes_manager.remove_attr_from_user(attribute_name, revoked_user_name)

        # Get List of the users affected. (The users who hold this attribute)
        affected_users_names = attributes_manager.attrs_to_users_dict[attribute_name]
        updated_KEK_dict = {}
        for a_user_name in affected_users_names:
            user_attribute_names_list = attributes_manager.users_to_attrs_dict[a_user_name]
            # KEK generation by AM
            new_user_KEK = self.user_attributes_kek_generation(attributes_manager.users_init_kek_dict[a_user_name],
                                                               attributes_manager,
                                                               user_attribute_names_list,
                                                               a_user_name)
            updated_KEK_dict[a_user_name] = new_user_KEK
        return updated_KEK_dict

    def add_attribute(self, user_name, attribute_name, SK_theta, UID: str, attributes_manager: AM, PP, MPK_m, g_gamma, gamma_i):
        """
        This function is executed by AM when an attribute is added to a user.
        Inputs:
            - user_name: The name of the user who has an attribute to be added.
            - attribute_name: To be added attribute name.
            - SK_theta: Secret key of the attribute issuer (theta).
            - UID: User_i ID.
            - attributes_manager: AM.
            - PP: Public Parameters from the system setup algorithm.
            - MPK_m: Manager (AM_m) public key represented as a dictionary.
        Outputs:
            - DSK_i_theta_u: The new DSK for the user (i) issued by AI (theta) for the attribute (u).
            - updated_KEK_dict: The key is the user-name of the user whose KEK key is updated and the value is the
                                updated KEK key value.
        """
        # AI updates D_i, D_i_tilde and send it to the user for him to append it to his DSK
        DSK_i_theta_u, kek_theta = self.attribute_key_gen([attribute_name], SK_theta, UID, MPK_m, PP, g_gamma, gamma_i)
        attributes_manager.users_init_kek_dict[user_name].update(kek_theta)

        # AM updates the users tree and returns to each affected user its updated KEK for this attribute.
        attributes_manager.add_attr_to_user(attribute_name, user_name)
        list_of_users_hold_attr = attributes_manager.attrs_to_users_dict[attribute_name]
        KEK_user_names_dict_for_attr = {}  # Each user gets an entry from this dict that is associated to him and
        # adds/updates it in his KEK.
        for a_user in list_of_users_hold_attr:
            KEK_attr = self.__generate_kek_for_user_with_attr(attributes_manager.users_init_kek_dict[a_user],
                                                            attribute_name, attributes_manager, a_user)
            KEK_user_names_dict_for_attr[a_user] = KEK_attr

        return DSK_i_theta_u, KEK_user_names_dict_for_attr


def main():
    group_obj = PairingGroup('SS512')

    attributes_authorities_list = [
        {
            'name': 'TA1',
            'controlled_attrs_names_list': ['ONE', 'TWO', 'THREE', 'FOUR']
        },
        {
            'name': 'TA2',
            'controlled_attrs_names_list': ['FIVE', 'SIX']
        }
    ]
    attributes_managers_cfg_list = [
        {
            'name': 'AM1',
            'controlled_users': ['U1', 'U2', 'U3', 'U4', 'U5', 'U6', 'U7', 'U8']
        }
    ]

    users_cfg_dict = {
        'U1': {
            'attributes': ['ONE@TA1', 'FOUR@TA1', 'TWO@TA1', 'SIX@TA2'],
            'associated_AM': 'AM1'
        },
        'U2': {
            'attributes': ['ONE@TA1', 'THREE@TA1'],
            'associated_AM': 'AM1'
        },
        'U3': {
            'attributes': ['ONE@TA1'],
            'associated_AM': 'AM1'
        },
        'U4': {
            'attributes': ['THREE@TA1'],
            'associated_AM': 'AM1'
        },
        'U5': {
            'attributes': ['ONE@TA1'],
            'associated_AM': 'AM1'
        },
        'U6': {
            'attributes': ['TWO@TA1'],
            'associated_AM': 'AM1'
        },
        'U7': {
            'attributes': ['ONE@TA1'],
            'associated_AM': 'AM1'
        },
        'U8': {
            'attributes': ['THREE@TA1'],
            'associated_AM': 'AM1'
        },
    }
    attribute_managers_dict = {}
    for am_cfg in attributes_managers_cfg_list:
        am_name = am_cfg['name']
        controlled_users = am_cfg['controlled_users']
        attributes_manager = AM(am_cfg, group_obj)
        for user_name in controlled_users:
            user_cfg = users_cfg_dict[user_name]
            assert user_cfg['associated_AM'] == am_name, \
                "The associated AM for the user does not match with the current AM name."
            for attr_name in user_cfg['attributes']:
                attributes_manager.add_attr_to_user(attr_name, user_name)

        am_cfg['obj'] = attributes_manager
        attribute_managers_dict[am_name] = attributes_manager
        print("Users attributes list: ", attributes_manager.users_to_attrs_dict)

    mabera = MABERA(group_obj)
    PP = mabera.system_setup()
    print("PP: ", PP)

    attr_authorities_pk_sk_dict = {}
    for attr_authority_dict in attributes_authorities_list:
        name = attr_authority_dict['name']
        PK_theta, SK_theta = mabera.authority_setup(name, PP)
        attr_authorities_pk_sk_dict[name] = {'PK_theta': PK_theta,
                                             'SK_theta': SK_theta}
        print("Attribute Authority {} PK: {}, SK: {}".format(name, PK_theta, SK_theta))

    attr_managers_pk_sk_dict = {}
    for an_AM_name in attribute_managers_dict:
        an_AM = attribute_managers_dict[an_AM_name]
        an_am_cfg = an_AM.am_cfg
        am_name = an_am_cfg['name']
        attributes_names_list = get_list_of_attr_names_controlled_by_AM(an_am_cfg, users_cfg_dict)
        MMK_m, MPK_m = mabera.manager_setup(attributes_names_list, PP)
        attr_managers_pk_sk_dict[am_name] = {'MMK_m': MMK_m, 'MPK_m': MPK_m}
        print("Manager {}: {}".format(am_name, attr_managers_pk_sk_dict[am_name]))

    users_secret_keys = {}
    for a_user_name, a_user_cfg in users_cfg_dict.items():
        UID = a_user_name
        attributes_dict = get_attributes_categorized_by_AI_dict(a_user_cfg['attributes']) # AI name is the key
        associated_AM_name = a_user_cfg['associated_AM']
        MPK_m = attr_managers_pk_sk_dict[associated_AM_name]['MPK_m']
        DSK_i = {'D_u_dict': {}, 'D_u_dash_dict': {}}
        kek_init = {}
        g_gamma, gamma_i = mabera.attribute_key_gen_user_part(PP['g'])

        for AI_name, attrs_list_by_AI in attributes_dict.items():
            SK_theta = attr_authorities_pk_sk_dict[AI_name]['SK_theta']
            DSK_i_theta, kek_theta = mabera.attribute_key_gen(attrs_list_by_AI, SK_theta, UID, MPK_m, PP, g_gamma, gamma_i)
            kek_init.update(kek_theta)
            DSK_i['D_u_dict'].update(DSK_i_theta['D_u_dict'])
            DSK_i['D_u_dash_dict'].update(DSK_i_theta['D_u_dash_dict'])

        # user_attributes_kek_generation(self, init_kek, attributes_manager, user_attribute_names_list, user_name)
        AM_obj = attribute_managers_dict[associated_AM_name]
        KEK_i = mabera.user_attributes_kek_generation(kek_init, AM_obj, a_user_cfg['attributes'], a_user_name)

        users_secret_keys[a_user_name] = {'DSK_i': DSK_i, 'KEK_i': KEK_i, 'gamma_i': gamma_i}
        print("DSK for user {}: {}".format(a_user_name, users_secret_keys[a_user_name]))

    # Encrypt the message.
    policy = "ONE@TA1 and TWO@TA1"
    M = group_obj.random(GT)
    attributes_issuer_pks = get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP)
    print("CT: ", CT)
    print("K_dash: ", K_dash)

    Hdr_m_dict = {}
    for an_AM_name in attribute_managers_dict:
        am = attribute_managers_dict[an_AM_name]
        MMK_m = attr_managers_pk_sk_dict[an_AM_name]['MMK_m']
        Hdr_m_dict[an_AM_name] = mabera.generate_ciphertext_headers(K_dash, MMK_m, am, a_xs_dict, PP)
    print("Hdr: ", Hdr_m_dict)

    # U1 will try to decrypt
    a_user_cfg = users_cfg_dict['U1']
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    dec_msg = mabera.decrypt(PP, CT, Hdr_m_dict[associated_AM_name], users_secret_keys['U1'], 'U1', 'U1', am)
    print("Decrypted Message: ", dec_msg)
    assert M == dec_msg, "FAILED Decryption: message is incorrect"

    # Revoke the attribute `TWO` from user `U1`
    a_user_cfg = users_cfg_dict['U1']
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    updated_users_KEK_values = mabera.revoke_attribute('U1', 'TWO@TA1', am)
    for a_user_name in updated_users_KEK_values:  # The updated users KEK keys need to be distributed to the users
        users_secret_keys[a_user_name]['KEK_i'].update(updated_users_KEK_values[a_user_name])

    policy = "ONE@TA1 and TWO@TA1 and SIX@TA2"
    M = group_obj.random(GT)
    attributes_issuer_pks = get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP)
    print("CT: ", CT)
    print("K_dash: ", K_dash)
    Hdr_m_dict = {}
    for an_AM_name in attribute_managers_dict:
        am = attribute_managers_dict[an_AM_name]
        MMK_m = attr_managers_pk_sk_dict[an_AM_name]['MMK_m']
        Hdr_m_dict[an_AM_name] = mabera.generate_ciphertext_headers(K_dash, MMK_m, am, a_xs_dict, PP)
    print("Hdr: ", Hdr_m_dict)

    # U1 will try to decrypt, but this time he will not be able to, because his attribute "TWO@TA1" is revoked.
    a_user_cfg = users_cfg_dict['U1']
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    # Uncomment to see the raised error.
    # dec_msg = mabera.decrypt(PP, CT, Hdr_m_dict[associated_AM_name], users_secret_keys['U1'], 'U1', 'U1', am)
    # print("Decrypted Message: ", dec_msg)
    # assert M == dec_msg, "FAILED Decryption: message is incorrect"

    # Add attribute "TWO@TA1" for user "U7".
    user_name = "U7"
    attr_to_be_added = "TWO@TA1"
    SK_theta = attr_authorities_pk_sk_dict['TA1']['SK_theta']
    a_user_cfg = users_cfg_dict[user_name]
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    MPK_m = attr_managers_pk_sk_dict[associated_AM_name]['MPK_m']
    gamma_i = users_secret_keys[user_name]['gamma_i']
    g_gamma = PP['g'] ** gamma_i
    DSK_i_theta_u, KEK_user_names_dict_for_attr = mabera.add_attribute(user_name, attr_to_be_added, SK_theta,
                                                                       user_name, am, PP, MPK_m, g_gamma, gamma_i)
    users_secret_keys[user_name]['DSK_i']['D_u_dict'].update(DSK_i_theta_u['D_u_dict'])
    users_secret_keys[user_name]['DSK_i']['D_u_dash_dict'].update(DSK_i_theta_u['D_u_dash_dict'])

    # Each user receives the updated KEK for the attribute
    for a_user_name in KEK_user_names_dict_for_attr:
        user_KEK_for_added_attr = KEK_user_names_dict_for_attr[a_user_name]  # KEK for attribute 'TWO@TA1' for a
        # specific user.
        user_private_keys_dict = users_secret_keys[a_user_name]
        KEK_for_user = user_private_keys_dict['KEK_i']
        KEK_for_user[attr_to_be_added] = user_KEK_for_added_attr

    print("{} new secret key {}".format(user_name, users_secret_keys[a_user_name]))
    # Encrypt the message. AB: Only re-encryption is required to generate the new Hdr, which means that the user is not obliged to encrypt again.
    policy = "ONE@TA1 and TWO@TA1"
    M = group_obj.random(GT)
    attributes_issuer_pks = get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP)
    print("CT: ", CT)
    print("K_dash: ", K_dash)
    Hdr_m_dict = {}
    for an_AM_name in attribute_managers_dict:
        am = attribute_managers_dict[an_AM_name]
        MMK_m = attr_managers_pk_sk_dict[an_AM_name]['MMK_m']
        Hdr_m_dict[an_AM_name] = mabera.generate_ciphertext_headers(K_dash, MMK_m, am, a_xs_dict, PP)
    print("Hdr: ", Hdr_m_dict)

    # U7 will try to decrypt.
    user_name = "U7"
    a_user_cfg = users_cfg_dict[user_name]
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    dec_msg = mabera.decrypt(PP, CT, Hdr_m_dict[associated_AM_name], users_secret_keys[user_name], user_name, user_name,
                             am)
    print("Decrypted Message: ", dec_msg)
    assert M == dec_msg, "FAILED Decryption: message is incorrect"

    
    # UMK = {} # A value stored privately by TA for each user.
    # users_private_keys_dict = {}
    # users_kek_i = {} # Held privately by AM
    # for user_name in user_names_list:
    #     # Attribute key generation. Executed by TA.
    #     user_attribute_names_list = attributes_manager.users_to_attrs_dict[user_name]
    #     # KEK generation by AM.
    #     DSK, KEK = mabera.key_generation(PP, MK, MPK_m, user_attribute_names_list, user_name, attributes_manager,
    #                                      UMK, users_kek_i)
    #     users_private_keys_dict[user_name] = {'DSK': DSK, 'KEK': KEK}
    #     print("KEK for {}: {}".format(user_name, users_private_keys_dict[user_name]))
    # 
    # rand_msg = group_obj.random(GT)
    # print("Message: ", rand_msg)
    # policy_str = '((four or three) and (three or one))'
    # CT_tilde, Hdr = mabera.encrypt(PP, MMK_m, rand_msg, policy_str, attributes_manager)
    # print("CT: ", CT_tilde)
    # user_private_keys_dict = users_private_keys_dict['U2']
    # DSK = user_private_keys_dict['DSK']
    # KEK = user_private_keys_dict['KEK']
    # recovered_M = mabera.decrypt(PP, CT_tilde, Hdr, DSK, KEK, 'U2', attributes_manager)
    # print('Recovered Message: ', recovered_M)
    # assert rand_msg == recovered_M, "FAILED Decryption: message is incorrect"
    # 
    # # Revoke the attribute `THREE` from user `U2`
    # updated_users_kek_values = mabera.revoke_attribute('U2', 'THREE', attributes_manager, PP, users_kek_i, MMK_m,
    #                                                         MPK_m)
    # for a_user_name in updated_users_kek_values:  # The updated users KEK keys need to be distributed to the users
    #     users_private_keys_dict[user_name]['KEK'] = updated_users_kek_values[a_user_name]
    # 
    # # Now `U7` does not have the ability to decrypt the message because his attributes ['ONE'] does not match the policy
    # user_private_keys_dict = users_private_keys_dict['U7']
    # DSK = user_private_keys_dict['DSK']
    # KEK = user_private_keys_dict['KEK']
    # recovered_M = mabera.decrypt(PP, CT_tilde, Hdr, DSK, KEK, 'U7', attributes_manager)
    # print("Wrong recovered M for U7: ", recovered_M)
    # # Uncomment the following line and an error will be raised
    # # assert rand_msg == recovered_M, "FAILED Decryption: message is incorrect"
    # 
    # # Add attribute `FOUR` to user `U7`
    # attr_to_be_added = 'FOUR'
    # D_i, D_i_tilde, KEK_user_names_dict_for_attr = mabera.add_attribute('U7', attr_to_be_added, attributes_manager,
    #                                                                          PP, UMK, users_kek_i, MMK_m, MPK_m)
    # user_private_keys_dict = users_private_keys_dict['U7']
    # # Update DSK for the user
    # DSK = user_private_keys_dict['DSK']
    # DSK['D_i'][attr_to_be_added] = D_i
    # DSK['D_i_dash'][attr_to_be_added] = D_i_tilde
    # DSK['attrs'].append(attr_to_be_added)
    # # Each user receives the updated KEK for the attribute 'U7'
    # for a_user_name in KEK_user_names_dict_for_attr:
    #     user_KEK_for_added_attr = KEK_user_names_dict_for_attr[a_user_name]  # KEK for attribute 'FOUR' for a specific
    #     # user.
    #     user_private_keys_dict = users_private_keys_dict[a_user_name]
    #     KEK_for_user = user_private_keys_dict['KEK']
    #     KEK_for_user[attr_to_be_added] = user_KEK_for_added_attr
    # 
    # # Encrypt the same message again.
    # CT_tilde, Hdr = mabera.encrypt(PP, MMK_m, rand_msg, policy_str, attributes_manager)
    # print("CT: ", CT_tilde)
    # user_private_keys_dict = users_private_keys_dict['U2']
    # DSK = user_private_keys_dict['DSK']
    # KEK = user_private_keys_dict['KEK']
    # # Now `U2` does not have the ability to decrypt the message because his attributes no longer match the policy after
    # # one of his attributes was revoked.
    # recovered_M = mabera.decrypt(PP, CT_tilde, Hdr, DSK, KEK, 'U2', attributes_manager)
    # print("Wrong recovered M for U2: ", recovered_M)
    # # Uncomment the following line and an error will be raised
    # # assert rand_msg == recovered_M, "FAILED Decryption: message is incorrect"
    # 
    # # U7 now has the ability to decrypt the message after because his attributes now match the policy [ONE, FOUR]
    # user_private_keys_dict = users_private_keys_dict['U7']
    # DSK = user_private_keys_dict['DSK']
    # KEK = user_private_keys_dict['KEK']
    # # `U7` has the ability to decrypt the message because his attributes match the policy after adding attribute FOUR
    # recovered_M = mabera.decrypt(PP, CT_tilde, Hdr, DSK, KEK, 'U7', attributes_manager)
    # print("Recovered M for U7: ", recovered_M)
    # assert rand_msg == recovered_M, "FAILED Decryption: message is incorrect"


def get_authorities_public_keys_dict(attr_authorities_pk_sk_dict):
    attr_auth_pk_dict = {}
    for attr_auth_name in attr_authorities_pk_sk_dict:
        attr_auth_dict = attr_authorities_pk_sk_dict[attr_auth_name]
        attr_auth_pk_dict[attr_auth_name] = attr_auth_dict['PK_theta']
    return attr_auth_pk_dict


def get_list_of_attr_names_controlled_by_AM(an_AM, users_cfg_dict):
    """
    Get list of attributes controlled by the attributes manager.
    Inputs:
        - an_AM: Attribute manager cfg.

    Outputs:
        - attributes_names_list: Names of the attributes.
    """
    attributes_names_set = set()
    for a_user_name in an_AM['controlled_users']:
        a_user = users_cfg_dict[a_user_name]
        for an_attr in a_user['attributes']:
            attributes_names_set.add(an_attr)
    return list(attributes_names_set)


def get_attributes_categorized_by_AI_dict(attr_names_list: List[str]) -> Dict[str, List[str]]:
    """
    Get attributes categorized by Attribute Issuer (AI) as a dictionary.
    Inputs:
     - attr_names_list: A list of attribute names, where each attribute is in the following format 'attrName@AI'.
    Outputs:
     - attr_names_dict: A dictionary where the key is the AI name and the value is a list of attributes controlled by
                        this AI.
    """
    attr_names_dict = {}
    for attr_name in attr_names_list:
        AI_name = attr_name.split('@')[1]
        if AI_name not in attr_names_dict:
            attr_names_dict[AI_name] = []
        attr_names_dict[AI_name].append(attr_name)
    return attr_names_dict


if __name__ == "__main__":
    main()