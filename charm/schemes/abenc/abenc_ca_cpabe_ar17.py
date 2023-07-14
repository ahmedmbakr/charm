'''
Jiguo Li, Wei Yao, Jinguang Han, Yichen Zhang, Jian Shen (Pairing-based)

| From: "User Collusion Avoidance CP-ABE With Efficient Attribute Revocation for Cloud Storage".
| Published in: 2017
| Available from: https://ieeexplore.ieee.org/abstract/document/7867082
| Notes: The code from the file 'abenc_bsw07.py' was taken as a starting point, since this scheme is based on that paper
|        implemented in that script.
| Security Assumption:
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    Ahmed Bakr
:Date:            07/2023
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output

from typing import Dict, List

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':str }
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2 }


import queue


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
    def __init__(self, groupObj):
        self.group = groupObj
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
    def __init__(self, group_obj):
        self.users_to_attrs_dict: Dict[str, list] = {}
        self.attrs_to_users_dict: Dict[str, list] = {}

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

    def get_minimum_nodes_list_that_represent_users_list(self, user_names_list: List[str]):
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

        visited_arr[node.sequence_number] = visited_arr[node.left.sequence_number] and visited_arr[
            node.right.sequence_number]

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

debug = False


class CaCPabeAr(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

def main():
    group_obj = PairingGroup('SS512')

    user_names_list = ['U1', 'U2']
    attributes_manager = AM(group_obj)
    attributes_manager.add_attr_to_user('ONE', 'U1')
    attributes_manager.add_attr_to_user('TWO', 'U1')
    attributes_manager.add_attr_to_user('TWO', 'U2')
    attributes_manager.add_attr_to_user('ONE', 'U2')
    attributes_manager.add_attr_to_user('THREE', 'U2')
    attributes_manager.add_attr_to_user('ONE', 'U3')
    attributes_manager.add_attr_to_user('ONE', 'U4')
    attributes_manager.add_attr_to_user('ONE', 'U5')
    attributes_manager.add_attr_to_user('ONE', 'U6')
    attributes_manager.add_attr_to_user('ONE', 'U7')
    attributes_manager.add_attr_to_user('ONE', 'U8')
    print(attributes_manager.users_to_attrs_dict)
    attributes_manager.remove_attr_from_user('TWO', 'U2')
    print(attributes_manager.users_to_attrs_dict)

    print(attributes_manager.users_binary_tree.print_tree())
    print("User Assignation to leafs dict: ", attributes_manager.get_user_assignation_to_leafs_dict())

    user_names_list = ['U1', 'U2', 'U3', 'U4', 'U7', 'U8']
    min_tree_nodes_list = attributes_manager.get_minimum_nodes_list_that_represent_users_list(user_names_list)
    print(min_tree_nodes_list)


if __name__ == "__main__":
    main()