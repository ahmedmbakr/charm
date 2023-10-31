import numpy as np
import math
import matplotlib.pyplot as plt


def draw_num_leafs_against_num_users(paper_citation_num, bytes_per_node=24):
    """This function is to show that our scheme is more efficient for large number of users, as their solution has only
    one AM, but ours allows the usage of many AMs.
    """
    num_users_list = [10, 10**2, 10**3, 10**4, 10**5, 10**6, 10**7, 10**8] # Fixed x-axis values
    num_AMs_configurations = [1, 2, 10, 100] # When AM is 1, I mean the paper I am comparing with.
    graph_colors_list = ['r', 'b', 'g', 'c']
    labels_list = [paper_citation_num, 'Our scheme with 2 AMs', 'Our scheme with 10 AMs', 'Our scheme with 100 AMs']

    num_tree_nodes_dict = {} # Calculate number of leafs needed for each categorization
    # Initialize num_leafs_dict for our solution configuration
    for num_AMs in num_AMs_configurations:
        num_tree_nodes_dict[num_AMs] = []
    for num_users in num_users_list:
        for idx, num_AMs in enumerate(num_AMs_configurations):
            if num_AMs > num_users:
                num_tree_nodes_dict[num_AMs].append(0)
                continue
            num_users_per_AM = num_users // num_AMs
            if num_users_per_AM % num_AMs != 0:
                num_users_per_AM += 1

            tree_level = math.ceil(math.log(num_users_per_AM, 2))
            num_nodes = 2 ** (tree_level + 1) - 1
            num_tree_nodes_dict[num_AMs].append(num_nodes * bytes_per_node) # AB: A workaround to convert the number of nodes to bytes without many changes in the code
    print(num_tree_nodes_dict)

    fig = plt.figure()
    plt.xlabel('Num. users')
    plt.ylabel('Tree storage overhead (bytes)')
    # plt.title('N')
    for idx, num_AMs in enumerate(num_AMs_configurations):
        plt.plot(num_users_list, num_tree_nodes_dict[num_AMs], '{}'.format(graph_colors_list[idx]),
                 label='{}'.format(labels_list[idx]))
    plt.legend()
    # fig.show()
    plt.show(block=True)


if __name__ == "__main__":
    DIFFERENTIATE_WITH_PAPER_NUMBER = "[14]"  # This is the citation number in the paper.
    draw_num_leafs_against_num_users(DIFFERENTIATE_WITH_PAPER_NUMBER)
