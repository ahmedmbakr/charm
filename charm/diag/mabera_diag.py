import numpy as np
import math, os, pickle
import matplotlib.pyplot as plt
from mabera_eval_cfg import SIMULATION_DICT


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


def draw_num_users_vs_num_attrs_vs_enc_time(cfg):
    import numpy as np
    from matplotlib.lines import Line2D
    pickle_file_full_path = os.path.abspath(cfg['reported_enc_time_vs_num_users_vs_num_attrs_pickle_path'].format(0))  # Display the output from the first run.
    reported_times_per_AM_dict = pickle.load(open(pickle_file_full_path, mode='rb'))
    labels_list = cfg['labels_list']
    graph_colors_list = cfg['graph_colors_list']
    fig = plt.figure()
    ax = plt.axes(projection='3d')
    # Data for three-dimensional scattered points
    for idx, num_AMs in enumerate(reported_times_per_AM_dict):
        xdata = np.array(reported_times_per_AM_dict[num_AMs]['num_users'])
        ydata = np.array(reported_times_per_AM_dict[num_AMs]['num_attrs'])
        zdata = np.array(reported_times_per_AM_dict[num_AMs]['overall_enc_time'])
        zdata = zdata / 1000  # Convert ms to seconds
        # ax.scatter3D(xdata, ydata, zdata, c=zdata, cmap='viridis', marker='^', label='{}'.format(labels_list[idx]))
        ax.scatter3D(xdata, ydata, zdata, color='{}'.format(graph_colors_list[idx]), label='{}'.format(labels_list[idx]))
        surf = ax.plot_trisurf(xdata, ydata, zdata, color='{}'.format(graph_colors_list[idx]), alpha=0.2)
    # Add a legend to the figure
    plt.legend(loc="upper right")
    ax.set_xlabel('Num. users')
    ax.set_ylabel('Num. attributes')
    ax.set_zlabel('Overall encryption time (s)')
    plt.show(block=True)


if __name__ == "__main__":
    DIFFERENTIATE_WITH_PAPER_NUMBER = "CA-ABE"  # This is the citation number in the paper.
    # draw_num_leafs_against_num_users(DIFFERENTIATE_WITH_PAPER_NUMBER)
    draw_num_users_vs_num_attrs_vs_enc_time(SIMULATION_DICT['enc_time_vs_num_users_vs_num_attrs_exp_cfg'])
