import copy
import numpy as np
import math, os, pickle
import matplotlib as mpl
import matplotlib.pyplot as plt
from mabera_eval_cfg import SIMULATION_DICT
from typing import List, Tuple, Dict

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


def draw_num_users_vs_num_attrs_vs_enc_time(cfg, pickle_num='avg', repeat_simulation_counter=None):
    import numpy as np
    from matplotlib.lines import Line2D

    path_before_substitution_str = cfg['reported_enc_time_vs_num_users_vs_num_attrs_pickle_path']
    if pickle_num == 'avg':
        reported_times_per_AM_dict = get_avgeraged_dict(path_before_substitution_str, repeat_simulation_counter)
    else:
        pickle_file_full_path = os.path.abspath(
            path_before_substitution_str.format(pickle_num))  # Display the output from the first run.
        reported_times_per_AM_dict = pickle.load(open(pickle_file_full_path, mode='rb'))

    labels_list = cfg['labels_list']
    graph_colors_list = cfg['graph_colors_list']
    fig = plt.figure()
    ax = plt.axes(projection='3d')
    # Data for three-dimensional scattered points
    fake_lines = []
    for idx, num_AMs in enumerate(reported_times_per_AM_dict):
        xdata = np.array(reported_times_per_AM_dict[num_AMs]['num_users'])
        ydata = np.array(reported_times_per_AM_dict[num_AMs]['num_attrs'])
        zdata = np.array(reported_times_per_AM_dict[num_AMs]['overall_enc_time'])
        zdata = zdata / 1000  # Convert ms to seconds
        surf = ax.plot_trisurf(xdata, ydata, zdata, color='{}'.format(graph_colors_list[idx]), alpha=0.2)
        fake2Dline = mpl.lines.Line2D([0], [0], linestyle="none", c='{}'.format(graph_colors_list[idx]), marker='o')
        fake_lines.append(fake2Dline)
    # ax.legend(fake_lines, labels_list, numpoints=1)
    # Add a legend to the figure
    # plt.legend(loc="upper right")
    ax.set_xlabel('Num. users')
    ax.set_ylabel('Num. attributes')
    ax.set_zlabel('Overall encryption time (s)')
    ax.invert_xaxis()
    plt.show(block=True)


def draw_enc_dec_times_vs_num_attributes(cfg, pickle_num='avg', repeat_simulation_counter=None):
    path_before_substitution_str = cfg['reported_times_per_AM_dict_pickle_path']
    if pickle_num == 'avg':
        reported_times_per_AM_dict = get_avgeraged_dict(path_before_substitution_str, repeat_simulation_counter)
    else:
        pickle_file_full_path = os.path.abspath(
            path_before_substitution_str.format(pickle_num))  # Display the output from the first run.
        reported_times_per_AM_dict = pickle.load(open(pickle_file_full_path, mode='rb'))

    total_num_users = cfg['total_num_users']
    labels_list = cfg['labels_list']
    graph_colors_list = cfg['graph_colors_list']

    fig = plt.figure()
    # Draw the encryption graph.
    ax = plt.subplot(1, 2, 1)
    plt.xlabel('Num. attributes')
    plt.ylabel('Enc. Time (ms)')
    for idx, num_AMs in enumerate(reported_times_per_AM_dict):
        plt.plot(reported_times_per_AM_dict[num_AMs]['num_attrs'],
                 reported_times_per_AM_dict[num_AMs]['overall_enc_time'], '{}'.format(graph_colors_list[idx]),
                 label='{}'.format(labels_list[idx]))
    plt.legend()
    plt.title('Enc execution times when num users={}'.format(total_num_users))

    # Draw the encryption graph.
    ax = plt.subplot(1, 2, 2)
    plt.xlabel('Num. attributes')
    plt.ylabel('Dec. Time (ms)')
    for idx, num_AMs in enumerate(reported_times_per_AM_dict):
        plt.plot(reported_times_per_AM_dict[num_AMs]['num_attrs'],
                 reported_times_per_AM_dict[num_AMs]['overall_dec_time'], '{}'.format(graph_colors_list[idx]),
                 label='{}'.format(labels_list[idx]))

    plt.legend()
    plt.title('Dec execution times when num users={}'.format(total_num_users))
    plt.show(block=True)

def draw_all_attrs(cfg, pickle_num='avg', repeat_simulation_counter=None, show_encryption_time_enabled=True):
    import pandas as pd
    path_before_substitution_str = cfg['reported_all_algorithm_times_pickle_path']
    if pickle_num == 'avg':
        reported_times_dict = get_avgeraged_dict(path_before_substitution_str, repeat_simulation_counter)
    else:
        pickle_file_full_path = os.path.abspath(
            path_before_substitution_str.format(pickle_num))  # Display the output from the first run.
        reported_times_dict = pickle.load(open(pickle_file_full_path, mode='rb'))

    ca_abe_reported_times_dict = reported_times_dict['CA-ABE']
    mabera_reported_times_dict = reported_times_dict['MABERA']
    total_num_users = cfg['total_num_users']
    total_num_attrs = cfg['total_num_attrs']
    labels_list = cfg['labels_list']
    graph_colors_list = cfg['graph_colors_list']

    # With Enc.
    if show_encryption_time_enabled:
        plotdata = pd.DataFrame({
            labels_list[0]: [ca_abe_reported_times_dict['auth_setup_time'], ca_abe_reported_times_dict['manager_setup_time'],
                       ca_abe_reported_times_dict['key_gen_time'],
                       ca_abe_reported_times_dict['enc_time'],
                       ca_abe_reported_times_dict['dec_time']],
            labels_list[1]: [mabera_reported_times_dict['auth_setup_time'], mabera_reported_times_dict['manager_setup_time'],
                       mabera_reported_times_dict['key_gen_time'],
                       mabera_reported_times_dict['enc_time'],
                       mabera_reported_times_dict['dec_time']]
        }, index=['Auth setup', 'Manager setup', 'Key gen', 'Encryption', 'Decryption'])
    else:
        # Without Enc.
        plotdata = pd.DataFrame({
            labels_list[0]: [ca_abe_reported_times_dict['auth_setup_time'],
                             ca_abe_reported_times_dict['manager_setup_time'],
                             ca_abe_reported_times_dict['key_gen_time'],
                             ca_abe_reported_times_dict['dec_time']],
            labels_list[1]: [mabera_reported_times_dict['auth_setup_time'],
                             mabera_reported_times_dict['manager_setup_time'],
                             mabera_reported_times_dict['key_gen_time'],
                             mabera_reported_times_dict['dec_time']]
        }, index=['Auth setup', 'Manager setup', 'Key gen', 'Decryption'])


    # ax = plotdata.plot(kind="barh", figsize=(15, 8), color=graph_colors_list, grid=True, logx=True)
    ax = plotdata.plot(kind="barh", figsize=(15, 8), color=graph_colors_list, grid=True)

    plt.title('Algorithms execution times when num users={}, num attrs={}'.format(total_num_users, total_num_attrs))
    plt.ylabel("Algorithms")
    plt.xlabel("Execution time (ms)")
    if show_encryption_time_enabled:
        plt.xlim([0, 3100])  # Adjust the limit for the x-axis
        plt.xlim([0, 400])  # Adjust the limit for the x-axis
        # plt.xlim([0, 2000])  # Adjust the limit for the x-axis
    else:
        plt.xlim([0, 100])  # Adjust the limit for the x-axis
    plt.show(block=True)


def get_avgeraged_dict(path_before_substitution_str, num_runs):
    assert type(num_runs) == int, "Number of runs has to be an integer number"

    # Read the pickle files into a list
    list_of_dicts = []
    for run_idx in range(num_runs):
        pickle_file_full_path = os.path.abspath(
            path_before_substitution_str.format(run_idx))  # Display the output from the first run.
        reported_times_per_AM_dict = pickle.load(open(pickle_file_full_path, mode='rb'))
        list_of_dicts.append(reported_times_per_AM_dict)

    avg_dict = {}
    for simulation_round_dict in list_of_dicts:
        for a_graph_key in simulation_round_dict:
            if a_graph_key not in avg_dict:
                avg_dict[a_graph_key] = {}
            for attr_name in simulation_round_dict[a_graph_key]:
                if 'time' not in attr_name:
                    if attr_name not in avg_dict[a_graph_key]:
                        avg_dict[a_graph_key][attr_name] = simulation_round_dict[a_graph_key][attr_name]
                    continue
                if attr_name not in avg_dict[a_graph_key]:
                    if type(simulation_round_dict[a_graph_key][attr_name]) == list:
                        avg_dict[a_graph_key][attr_name] = [0] * len(simulation_round_dict[a_graph_key][attr_name])
                    else:
                        avg_dict[a_graph_key][attr_name] = simulation_round_dict[a_graph_key][attr_name]
                if type(simulation_round_dict[a_graph_key][attr_name]) == list:
                    for idx, elem in enumerate(simulation_round_dict[a_graph_key][attr_name]):
                        avg_dict[a_graph_key][attr_name][idx] += elem / len(list_of_dicts)

    return avg_dict


if __name__ == "__main__":
    repeat_simulation_counter = SIMULATION_DICT['repeat_simulation_counter']
    DIFFERENTIATE_WITH_PAPER_NUMBER = "CA-ABE"  # This is the citation number in the paper.
    # draw_num_leafs_against_num_users(DIFFERENTIATE_WITH_PAPER_NUMBER)
    draw_num_users_vs_num_attrs_vs_enc_time(SIMULATION_DICT['enc_time_vs_num_users_vs_num_attrs_exp_cfg'], 'avg', repeat_simulation_counter=repeat_simulation_counter)
    # draw_enc_dec_times_vs_num_attributes(SIMULATION_DICT['enc_dec_time_vs_num_attrs_exp'], 'avg', repeat_simulation_counter=repeat_simulation_counter)
    # draw_all_attrs(SIMULATION_DICT['report_all_algorithm_times_exp_cfg'], 'avg', repeat_simulation_counter=repeat_simulation_counter, show_encryption_time_enabled=True)
