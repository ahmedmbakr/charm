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


class UsersBinaryTree:
    def __init__(self, groupObj):
        self.group = groupObj
        self.__leafs_queue = queue.Queue()
        self.__sequence_number = 0
        self.root = self.create_node()
        self.__leafs_queue.put(self.root)
        self.__curr_node = self.__leafs_queue.get()

    def create_node(self) -> TreeNode:
        self.__sequence_number += 1
        return TreeNode(self.__sequence_number, self.group.random(ZR))

    def add_node_to_tree(self, tree_node: TreeNode):
        """
        Add a node to the tree.
        Inputs:
            - tree_node: a node to be added to the tree
        """
        if self.__curr_node.left and self.__curr_node.right:
            assert not self.__leafs_queue.empty(), "Leafs queue is empty and pull attempts was made"
            self.__curr_node = self.__leafs_queue.get()
        if not self.__curr_node.left:
            self.__curr_node.left = tree_node
        elif not self.__curr_node.right:
            self.__curr_node.right = tree_node
        else:
            assert True, "This statement should not be reached"
        tree_node.parent = self.__curr_node
        self.__leafs_queue.put(tree_node)

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


debug = False
class Ca_CPabe_Aa(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

def main():
    groupObj = PairingGroup('SS512')
    users_binary_tree = UsersBinaryTree(groupObj)
    n2 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n2)
    n3 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n3)
    n4 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n4)
    n5 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n5)
    n6 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n6)
    n7 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n7)
    n8 = users_binary_tree.create_node()
    users_binary_tree.add_node_to_tree(n8)

    users_binary_tree.print_tree()

if __name__ == "__main__":
    main()