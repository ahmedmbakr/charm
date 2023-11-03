from mabera_eval_cfg import SIMULATION_DICT
import glob
from typing import List, Tuple, Dict
# from ..schemes.abenc.mabera_bakr23 import MABERA, TreeNode, UsersBinaryTree, AM, ShnorrInteractiveZKP
import os
import sys
import time
import random
import matplotlib.pyplot as plt
import pickle
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,hashPair
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.abspath(os.path.join(dir_path, '../schemes/abenc/')))
import mabera_bakr23 as mabera_f
import abenc_ca_cpabe_ar17 as cpabe_f


def enc_time_vs_num_attrs_exp(round_id, reported_times_per_AM_dict_pickle_path, cfg, header_regeneration_enabled=True):
    print("Experiment of number of attributes VS encryption time")
    total_num_users = cfg['total_num_users']
    min_num_attrs_per_user = cfg['min_num_attrs_per_user']
    max_num_attrs_per_user = cfg['max_num_attrs_per_user']
    inc_num_attrs_per_user = cfg['inc_num_attrs_per_user']
    disable_zkp = cfg['disable_zkp']
    draw = cfg['draw']
    tic = time.time()
    number_of_AMs_to_test = cfg['number_of_AMs_to_test']
    graph_colors_list = cfg['graph_colors_list']
    labels_list = cfg['labels_list']

    group_obj = PairingGroup('SS512')
    attributes_authorities_list = [
        {
            'name': 'TA1',
            'controlled_attrs_names_list': ['ONE', 'TWO', 'THREE', 'FOUR']
        }
    ]

    mabera = mabera_f.MABERA(group_obj)
    PP = mabera.system_setup()
    # print("PP: ", PP)

    attr_authorities_pk_sk_dict = {}
    for attr_authority_dict in attributes_authorities_list:
        name = attr_authority_dict['name']
        PK_theta, SK_theta = mabera.authority_setup(name, PP)
        attr_authorities_pk_sk_dict[name] = {'PK_theta': PK_theta,
                                             'SK_theta': SK_theta}
        # print("Attribute Authority {} PK: {}, SK: {}".format(name, PK_theta, SK_theta))

    reported_times_per_AM_dict = {}
    for num_AMs in number_of_AMs_to_test:
        original_num_AMs = num_AMs
        reported_times_per_AM_dict[num_AMs] = {'num_attrs': [], 'overall_enc_time': []}
        users_cfg_dict = {}
        for i in range(total_num_users):
            users_cfg_dict['U' + str(i)] = {'attributes': [], 'associated_AM': 'AM1'}  # This is an initial value.
        # Assign the users to AMs
        # Initialize AMs
        attributes_managers_cfg_list = []
        if num_AMs == 'CA-ABE':
            num_AMs = 1
        for an_AM_idx in range(num_AMs):
            an_AM = {'name': "AM{}".format(an_AM_idx), 'controlled_users': []}
            for user_idx in range(an_AM_idx, total_num_users, num_AMs):
                an_AM['controlled_users'].append('U{}'.format(user_idx))
                users_cfg_dict['U{}'.format(user_idx)]['associated_AM'] = 'AM{}'.format(an_AM_idx)
            attributes_managers_cfg_list.append(an_AM)

        for num_attrs in range(min_num_attrs_per_user, max_num_attrs_per_user, inc_num_attrs_per_user):
            if original_num_AMs == 'CA-ABE':
                # The main purpose of the function is to change the value reported_times_per_AM_dict['CA-ABE']
                 enc_time_vs_num_attrs_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs,
                                                                 users_cfg_dict, reported_times_per_AM_dict)
            else:
                # The main purpose of the function is to change the value reported_times_per_AM_dict[an_AM]
                enc_time_vs_num_attrs_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                            group_obj, mabera, num_AMs, num_attrs,
                                                            reported_times_per_AM_dict, users_cfg_dict, disable_zkp=disable_zkp, header_regeneration_enabled=header_regeneration_enabled)
            pickle.dump(reported_times_per_AM_dict, open(reported_times_per_AM_dict_pickle_path, 'wb'))
    if draw:
        fig = plt.figure()
        plt.xlabel('Num. attributes')
        plt.ylabel('Enc. Time (ms)')
        for idx, num_AMs in enumerate(reported_times_per_AM_dict):
            plt.plot(reported_times_per_AM_dict[num_AMs]['num_attrs'], reported_times_per_AM_dict[num_AMs]['overall_enc_time'], '{}'.format(graph_colors_list[idx]),
                     label='{}'.format(labels_list[idx]))
        plt.legend()
        plt.show(block=True)

    enc_time_vs_num_attrs_time = time.time() - tic
    print("Time taken to complete round {} of encryption time VS Num attributes experiment: {:.3f}s".format(round_id, enc_time_vs_num_attrs_time))
    return reported_times_per_AM_dict


def enc_time_vs_num_attrs_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs, users_cfg_dict, reported_times_per_AM_dict):
    # Initialize the users with their list of attributes.
    for user_name in users_cfg_dict:
        for attr_idx in range(num_attrs):
            if random.random() > 0.5:  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}'.format(attr_idx))
    # Build the tree for each AM
    attribute_managers_dict = {}
    for am_cfg in attributes_managers_cfg_list:  # This list will contain only one element.
        am_name = am_cfg['name']
        controlled_users = am_cfg['controlled_users']
        attributes_manager = cpabe_f.AM(group_obj)
        for user_name in controlled_users:
            user_cfg = users_cfg_dict[user_name]
            assert user_cfg['associated_AM'] == am_name, \
                "The associated AM for the user does not match with the current AM name."
            for attr_name in user_cfg['attributes']:
                attributes_manager.add_attr_to_user(attr_name, user_name)
        am_cfg['obj'] = attributes_manager
        attribute_managers_dict[am_name] = attributes_manager
        # print("Users attributes list: ", attributes_manager.users_to_attrs_dict)
    ca_cpabe_ar = cpabe_f.CaCpabeAr(group_obj)
    MK, PP = ca_cpabe_ar.system_setup()
    # print("MK: ", MK)
    # print("PP: ", PP)

    # AM setup
    attributes_names_list = mabera_f.get_list_of_attr_names_controlled_by_AM(am_cfg, users_cfg_dict)

    MMK, MPK = ca_cpabe_ar.manager_setup(attributes_names_list, PP)
    # print("MMK_m: ", MMK)
    # print("MPK_m: ", MPK)

    # Generate users KEK
    UMK = {}  # A value stored privately by TA for each user.
    users_private_keys_dict = {}
    users_kek_i = {}  # Held privately by AM
    for user_name in users_cfg_dict:
        # Attribute key generation. Executed by TA.
        if user_name not in attributes_manager.users_to_attrs_dict:
            continue # This means that the user does not have any attributes.
        user_attribute_names_list = attributes_manager.users_to_attrs_dict[user_name]
        # KEK generation by AM.
        DSK, KEK = ca_cpabe_ar.key_generation(PP, MK, MPK, user_attribute_names_list, user_name, attributes_manager,
                                              UMK, users_kek_i)
        users_private_keys_dict[user_name] = {'DSK': DSK, 'KEK': KEK}
        # print("KEK for {}: {}".format(user_name, users_private_keys_dict[user_name]))

    # Encrypt the message
    rand_msg = group_obj.random(GT)
    policy_str = "att0"
    for attr_idx in range(1, num_attrs):
        policy_str += " and ATT{}".format(attr_idx)
    tic = time.time()
    CT = ca_cpabe_ar.local_encryption(policy_str, rand_msg, PP)
    local_enc_time = (time.time() - tic) * 1000
    tic = time.time()
    CT, Hdr = ca_cpabe_ar.reencryption(CT, MMK, PP, attributes_manager)
    reencrypt_time = (time.time() - tic) * 1000
    overall_time = local_enc_time + reencrypt_time
    reported_times_per_AM_dict['CA-ABE']['num_attrs'].append(num_attrs)
    reported_times_per_AM_dict['CA-ABE']['overall_enc_time'].append(overall_time)
    print(
        "With the configurations: num atts: {}, num_AMs: 'CA-ABE', the local encryption time: {:.3f}ms, enc header time: {:.3f}ms, overall = {:.3f}ms".format(
            num_attrs, local_enc_time, reencrypt_time, overall_time))


def enc_time_vs_num_attrs_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                group_obj, mabera, num_AMs, num_attrs, reported_times_per_AM_dict,
                                                users_cfg_dict, disable_zkp=False, header_regeneration_enabled=True):
    # Initialize the users with their list of attributes.
    for user_name in users_cfg_dict:
        for attr_idx in range(num_attrs):
            if random.random() > 0.5:  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}@TA1'.format(attr_idx))
    # Build the tree for each AM
    attribute_managers_dict = {}
    for am_cfg in attributes_managers_cfg_list:
        am_name = am_cfg['name']
        controlled_users = am_cfg['controlled_users']
        attributes_manager = mabera_f.AM(am_cfg, group_obj)
        for user_name in controlled_users:
            user_cfg = users_cfg_dict[user_name]
            assert user_cfg['associated_AM'] == am_name, \
                "The associated AM for the user does not match with the current AM name."
            for attr_name in user_cfg['attributes']:
                attributes_manager.add_attr_to_user(attr_name, user_name)
        am_cfg['obj'] = attributes_manager
        attribute_managers_dict[am_name] = attributes_manager
        # print("Users attributes list: ", attributes_manager.users_to_attrs_dict)
    # Attribute managers setup.
    attr_managers_pk_sk_dict = {}
    for an_AM_name in attribute_managers_dict:
        an_AM = attribute_managers_dict[an_AM_name]
        an_am_cfg = an_AM.am_cfg
        am_name = an_am_cfg['name']
        attributes_names_list = mabera_f.get_list_of_attr_names_controlled_by_AM(an_am_cfg, users_cfg_dict)
        MMK_m, MPK_m = mabera.manager_setup(attributes_names_list, PP)
        attr_managers_pk_sk_dict[am_name] = {'MMK_m': MMK_m, 'MPK_m': MPK_m}
        # print("Manager {}: {}".format(am_name, attr_managers_pk_sk_dict[am_name]))
    # Generate users secret keys
    users_secret_keys = {}
    for a_user_name, a_user_cfg in users_cfg_dict.items():
        UID = a_user_name
        attributes_dict = mabera_f.get_attributes_categorized_by_AI_dict(a_user_cfg['attributes'])  # AI name is the key
        associated_AM_name = a_user_cfg['associated_AM']
        MPK_m = attr_managers_pk_sk_dict[associated_AM_name]['MPK_m']
        DSK_i = {'D_u_dict': {}, 'D_u_dash_dict': {}}
        kek_init = {}
        g_gamma, gamma_i = mabera.attribute_key_gen_user_part(PP['g'])

        for AI_name, attrs_list_by_AI in attributes_dict.items():
            SK_theta = attr_authorities_pk_sk_dict[AI_name]['SK_theta']
            DSK_i_theta, kek_theta = mabera.attribute_key_gen(attrs_list_by_AI, SK_theta, UID, MPK_m, PP,
                                                              g_gamma, gamma_i)
            kek_init.update(kek_theta)
            DSK_i['D_u_dict'].update(DSK_i_theta['D_u_dict'])
            DSK_i['D_u_dash_dict'].update(DSK_i_theta['D_u_dash_dict'])

        AM_obj = attribute_managers_dict[associated_AM_name]
        KEK_i = mabera.user_attributes_kek_generation(kek_init, AM_obj, a_user_cfg['attributes'], a_user_name)

        users_secret_keys[a_user_name] = {'DSK_i': DSK_i, 'KEK_i': KEK_i, 'gamma_i': gamma_i}
        # print("DSK for user {}: {}".format(a_user_name, users_secret_keys[a_user_name]))
    # Encrypt the message.
    policy = "att0@TA1"
    for attr_idx in range(1, num_attrs):
        policy += " and ATT{}@TA1".format(attr_idx)
    M = group_obj.random(GT)  # Random message
    attributes_issuer_pks = mabera_f.get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    tic = time.time()
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP)
    local_enc_time = (time.time() - tic) * 1000
    # print("CT: ", CT)
    # print("K_dash: ", K_dash)
    Hdr_m_dict = {}
    enc_header_gen_time = 0  # minimum value to compare with
    hdr_regeneration_by_enc_time = 0  # To increment
    for an_AM_name in attribute_managers_dict:
        am = attribute_managers_dict[an_AM_name]
        MMK_m = attr_managers_pk_sk_dict[an_AM_name]['MMK_m']
        tic = time.time()
        Hdr_m_dict[an_AM_name] = mabera.generate_ciphertext_headers_by_AM(K_dash, MMK_m, am, PP, zkp_enabled=disable_zkp)
        am_enc_header_gen_time = (time.time() - tic) * 1000
        # This function is executed by the encryptor. First, The encryptor verifies that the AM calculated the proof
        # correctly. Then, it changes internally the Hdr_m_dict for the decryptor to be able to decrypt.
        tic = time.time()
        if header_regeneration_enabled:
            mabera.regenerate_headers_by_encryptor(Hdr_m_dict[an_AM_name], a_xs_dict, PP)
        hdr_regeneration_by_enc_time += (time.time() - tic) * 1000
        enc_header_gen_time = max(enc_header_gen_time, am_enc_header_gen_time)
    # print("Hdr: ", Hdr_m_dict)
    if header_regeneration_enabled:
        overall_enc_time = local_enc_time + enc_header_gen_time + (hdr_regeneration_by_enc_time - enc_header_gen_time)
    else:
        overall_enc_time = local_enc_time + enc_header_gen_time
    reported_times_per_AM_dict[num_AMs]['num_attrs'].append(num_attrs)
    reported_times_per_AM_dict[num_AMs]['overall_enc_time'].append(overall_enc_time)
    average_hdr_regen_time = hdr_regeneration_by_enc_time / len(attribute_managers_dict)
    print(
        "With the configurations: num atts: {}, num_AMs: {}, the local encryption time: {:.3f}ms, enc header time: {:.3f}ms, hdr_regen time: {:.3f} = {:.3f}ms * {}, overall = {:.3f}ms".format(
            num_attrs, num_AMs, local_enc_time, enc_header_gen_time, hdr_regeneration_by_enc_time,
            average_hdr_regen_time, len(attribute_managers_dict), overall_enc_time))


def get_avgeraged_dict(list_of_dicts: List[Dict[str, Dict[str, int]]]):
    avg_dict = {}
    for simulation_round_dict in list_of_dicts:
        for a_graph_key in simulation_round_dict:
            if a_graph_key not in avg_dict:
                avg_dict[a_graph_key] = {}
            for attr_name in simulation_round_dict[a_graph_key]:
                if 'time' not in attr_name:
                    avg_dict[a_graph_key][attr_name] = simulation_round_dict[a_graph_key][attr_name][0]
                    continue
                if attr_name not in avg_dict[a_graph_key]:
                    avg_dict[a_graph_key][attr_name] = [0] * len(simulation_round_dict[a_graph_key][attr_name])
                for idx, elem in enumerate(simulation_round_dict[a_graph_key][attr_name]):
                    avg_dict[a_graph_key][attr_name][idx] += elem / len(list_of_dicts)

    return avg_dict


def main(simulation_dict):
    print("Current configurations: {}".format(simulation_dict))
    header_regeneration_enabled = simulation_dict['header_regeneration_enabled']
    enc_time_vs_num_attrs_exp_cfg = simulation_dict['enc_time_vs_num_attrs_exp']
    enc_time_vs_num_users_exp_cfg = simulation_dict['enc_time_vs_num_users_exp']
    enc_time_vs_num_users_vs_num_attrs_exp_cfg = simulation_dict['enc_time_vs_num_users_vs_num_attrs_exp_cfg']
    
    reported_times_per_AM_pickle_path = enc_time_vs_num_attrs_exp_cfg['reported_times_per_AM_dict_pickle_path']
    reported_times_per_AM_pickle_path = os.path.abspath(reported_times_per_AM_pickle_path)
    
    reported_enc_time_vs_num_users_pickle_path = enc_time_vs_num_users_exp_cfg['reported_enc_time_vs_num_users_pickle_path']
    reported_enc_time_vs_num_users_pickle_path = os.path.abspath(reported_enc_time_vs_num_users_pickle_path)

    reported_enc_time_vs_num_users_vs_num_attrs_pickle_path = enc_time_vs_num_users_vs_num_attrs_exp_cfg[
        'reported_enc_time_vs_num_users_vs_num_attrs_pickle_path']
    reported_enc_time_vs_num_users_vs_num_attrs_pickle_path = os.path.abspath(reported_enc_time_vs_num_users_vs_num_attrs_pickle_path)

    repeat_simulation_counter = simulation_dict['repeat_simulation_counter']
    list_enc_time_vs_num_attrs_dict = []
    list_enc_time_vs_num_users_dict = []
    list_enc_time_vs_num_users_vs_num_attrs_dict = []
    for i in range(repeat_simulation_counter):
        print("Simulation round: {}".format(i))
        if enc_time_vs_num_attrs_exp_cfg['enabled']:
            enc_time_vs_num_attrs_dict = enc_time_vs_num_attrs_exp(i, reported_times_per_AM_pickle_path.format(i),
                                                                   enc_time_vs_num_attrs_exp_cfg, header_regeneration_enabled=header_regeneration_enabled)
            list_enc_time_vs_num_attrs_dict.append(enc_time_vs_num_attrs_dict)

        if enc_time_vs_num_users_exp_cfg['enabled']:
            enc_time_vs_num_users_dict = enc_time_vs_num_users_exp(i, reported_enc_time_vs_num_users_pickle_path.format(i),
                                                                   enc_time_vs_num_users_exp_cfg, header_regeneration_enabled=header_regeneration_enabled)
            list_enc_time_vs_num_users_dict.append(enc_time_vs_num_users_dict)
            
        if enc_time_vs_num_users_vs_num_attrs_exp_cfg['enabled']:
            enc_time_vs_num_users_vs_num_attrs_dict = enc_time_vs_num_users_vs_num_attrs_exp(i,
                                                                   reported_enc_time_vs_num_users_vs_num_attrs_pickle_path.format(i),
                                                                   enc_time_vs_num_users_vs_num_attrs_exp_cfg)
            list_enc_time_vs_num_users_vs_num_attrs_dict.append(enc_time_vs_num_users_vs_num_attrs_dict)
    # enc_time_vs_num_attrs_dict = get_avgeraged_dict(list_enc_time_vs_num_attrs_dict)
    # print(enc_time_vs_num_attrs_dict)


def enc_time_vs_num_users_exp(round_id, pickle_file_path, cfg, header_regeneration_enabled=True):
    print("Experiment of number of users VS encryption time")
    total_num_attrs = cfg['total_num_attrs'] # TODO:
    min_num_users = cfg['min_num_users']
    max_num_users = cfg['max_num_users']
    inc_num_users = cfg['inc_num_users']
    disable_zkp = cfg['disable_zkp']
    draw = cfg['draw']
    tic = time.time()
    number_of_AMs_to_test = cfg['number_of_AMs_to_test']
    graph_colors_list = cfg['graph_colors_list']
    labels_list = cfg['labels_list']

    group_obj = PairingGroup('SS512')
    attributes_authorities_list = [
        {
            'name': 'TA1',
            'controlled_attrs_names_list': ['ONE', 'TWO', 'THREE', 'FOUR']
        }
    ]

    mabera = mabera_f.MABERA(group_obj)
    PP = mabera.system_setup()
    # print("PP: ", PP)

    attr_authorities_pk_sk_dict = {}
    for attr_authority_dict in attributes_authorities_list:
        name = attr_authority_dict['name']
        PK_theta, SK_theta = mabera.authority_setup(name, PP)
        attr_authorities_pk_sk_dict[name] = {'PK_theta': PK_theta,
                                             'SK_theta': SK_theta}
        # print("Attribute Authority {} PK: {}, SK: {}".format(name, PK_theta, SK_theta))

    reported_times_per_AM_dict = {}
    for num_AMs in number_of_AMs_to_test:
        original_num_AMs = num_AMs
        reported_times_per_AM_dict[num_AMs] = {'num_users': [], 'overall_enc_time': []}

        for num_users in range(min_num_users, max_num_users, inc_num_users):
            users_cfg_dict = {}
            for i in range(num_users):
                users_cfg_dict['U' + str(i)] = {'attributes': [], 'associated_AM': 'AM1'}  # This is an initial value.
            # Assign the users to AMs
            # Initialize AMs
            attributes_managers_cfg_list = []
            if num_AMs == 'CA-ABE':
                num_AMs = 1
            for an_AM_idx in range(num_AMs):
                an_AM = {'name': "AM{}".format(an_AM_idx), 'controlled_users': []}
                for user_idx in range(an_AM_idx, num_users, num_AMs):
                    an_AM['controlled_users'].append('U{}'.format(user_idx))
                    users_cfg_dict['U{}'.format(user_idx)]['associated_AM'] = 'AM{}'.format(an_AM_idx)
                attributes_managers_cfg_list.append(an_AM)

            if original_num_AMs == 'CA-ABE':
                # The main purpose of the function is to change the value reported_times_per_AM_dict['CA-ABE']
                 enc_time_vs_num_users_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, total_num_attrs,
                                                                 users_cfg_dict, reported_times_per_AM_dict)
            else:
                # The main purpose of the function is to change the value reported_times_per_AM_dict[an_AM]
                enc_time_vs_num_users_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                            group_obj, mabera, num_AMs, total_num_attrs,
                                                            reported_times_per_AM_dict, users_cfg_dict, disable_zkp=disable_zkp, header_regeneration_enabled=header_regeneration_enabled)

            pickle.dump(reported_times_per_AM_dict, open(pickle_file_path, 'wb'))
    if draw:
        fig = plt.figure()
        plt.xlabel('Num. Users')
        plt.ylabel('Enc. Time (ms)')
        for idx, num_AMs in enumerate(reported_times_per_AM_dict):
            plt.plot(reported_times_per_AM_dict[num_AMs]['num_users'], reported_times_per_AM_dict[num_AMs]['overall_enc_time'], '{}'.format(graph_colors_list[idx]),
                     label='{}'.format(labels_list[idx]))
        plt.legend()
        plt.show(block=True)

    enc_time_vs_num_users_time = time.time() - tic
    print("Time taken to complete round {} of encryption time VS Num users experiment: {:.3f}s".format(round_id, enc_time_vs_num_users_time))
    return reported_times_per_AM_dict

def enc_time_vs_num_users_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                group_obj, mabera, num_AMs, num_attrs, reported_times_per_AM_dict,
                                                users_cfg_dict, disable_zkp=False, header_regeneration_enabled=True):
    # Initialize the users with their list of attributes.
    for user_name in users_cfg_dict:
        for attr_idx in range(num_attrs):
            if random.random() > 0.5:  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}@TA1'.format(attr_idx))
    # Build the tree for each AM
    attribute_managers_dict = {}
    for am_cfg in attributes_managers_cfg_list:
        am_name = am_cfg['name']
        controlled_users = am_cfg['controlled_users']
        attributes_manager = mabera_f.AM(am_cfg, group_obj)
        for user_name in controlled_users:
            user_cfg = users_cfg_dict[user_name]
            assert user_cfg['associated_AM'] == am_name, \
                "The associated AM for the user does not match with the current AM name."
            for attr_name in user_cfg['attributes']:
                attributes_manager.add_attr_to_user(attr_name, user_name)
        am_cfg['obj'] = attributes_manager
        attribute_managers_dict[am_name] = attributes_manager
        # print("Users attributes list: ", attributes_manager.users_to_attrs_dict)
    # Attribute managers setup.
    attr_managers_pk_sk_dict = {}
    for an_AM_name in attribute_managers_dict:
        an_AM = attribute_managers_dict[an_AM_name]
        an_am_cfg = an_AM.am_cfg
        am_name = an_am_cfg['name']
        attributes_names_list = mabera_f.get_list_of_attr_names_controlled_by_AM(an_am_cfg, users_cfg_dict)
        MMK_m, MPK_m = mabera.manager_setup(attributes_names_list, PP)
        attr_managers_pk_sk_dict[am_name] = {'MMK_m': MMK_m, 'MPK_m': MPK_m}
        # print("Manager {}: {}".format(am_name, attr_managers_pk_sk_dict[am_name]))
    # Generate users secret keys
    users_secret_keys = {}
    for a_user_name, a_user_cfg in users_cfg_dict.items():
        UID = a_user_name
        attributes_dict = mabera_f.get_attributes_categorized_by_AI_dict(a_user_cfg['attributes'])  # AI name is the key
        associated_AM_name = a_user_cfg['associated_AM']
        MPK_m = attr_managers_pk_sk_dict[associated_AM_name]['MPK_m']
        DSK_i = {'D_u_dict': {}, 'D_u_dash_dict': {}}
        kek_init = {}
        g_gamma, gamma_i = mabera.attribute_key_gen_user_part(PP['g'])

        for AI_name, attrs_list_by_AI in attributes_dict.items():
            SK_theta = attr_authorities_pk_sk_dict[AI_name]['SK_theta']
            DSK_i_theta, kek_theta = mabera.attribute_key_gen(attrs_list_by_AI, SK_theta, UID, MPK_m, PP,
                                                              g_gamma, gamma_i)
            kek_init.update(kek_theta)
            DSK_i['D_u_dict'].update(DSK_i_theta['D_u_dict'])
            DSK_i['D_u_dash_dict'].update(DSK_i_theta['D_u_dash_dict'])

        AM_obj = attribute_managers_dict[associated_AM_name]
        KEK_i = mabera.user_attributes_kek_generation(kek_init, AM_obj, a_user_cfg['attributes'], a_user_name)

        users_secret_keys[a_user_name] = {'DSK_i': DSK_i, 'KEK_i': KEK_i, 'gamma_i': gamma_i}
        # print("DSK for user {}: {}".format(a_user_name, users_secret_keys[a_user_name]))
    # Encrypt the message.
    policy = "att0@TA1"
    for attr_idx in range(1, num_attrs):
        policy += " and ATT{}@TA1".format(attr_idx)
    M = group_obj.random(GT)  # Random message
    attributes_issuer_pks = mabera_f.get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    tic = time.time()
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP)
    local_enc_time = (time.time() - tic) * 1000
    # print("CT: ", CT)
    # print("K_dash: ", K_dash)
    Hdr_m_dict = {}
    enc_header_gen_time = 0  # minimum value to compare with
    hdr_regeneration_by_enc_time = 0  # To increment
    for an_AM_name in attribute_managers_dict:
        am = attribute_managers_dict[an_AM_name]
        MMK_m = attr_managers_pk_sk_dict[an_AM_name]['MMK_m']
        tic = time.time()
        Hdr_m_dict[an_AM_name] = mabera.generate_ciphertext_headers_by_AM(K_dash, MMK_m, am, PP, zkp_enabled=disable_zkp)
        am_enc_header_gen_time = (time.time() - tic) * 1000
        # This function is executed by the encryptor. First, The encryptor verifies that the AM calculated the proof
        # correctly. Then, it changes internally the Hdr_m_dict for the decryptor to be able to decrypt.
        tic = time.time()
        if header_regeneration_enabled:
            mabera.regenerate_headers_by_encryptor(Hdr_m_dict[an_AM_name], a_xs_dict, PP)
        hdr_regeneration_by_enc_time += (time.time() - tic) * 1000
        enc_header_gen_time = max(enc_header_gen_time, am_enc_header_gen_time)
    # print("Hdr: ", Hdr_m_dict)
    if header_regeneration_enabled:
        overall_enc_time = local_enc_time + enc_header_gen_time + (hdr_regeneration_by_enc_time - enc_header_gen_time)
    else:
        overall_enc_time = local_enc_time + enc_header_gen_time
    reported_times_per_AM_dict[num_AMs]['num_users'].append(len(users_cfg_dict))
    if 'num_attrs' in reported_times_per_AM_dict[num_AMs]:
        reported_times_per_AM_dict[num_AMs]['num_attrs'].append(num_attrs)
    reported_times_per_AM_dict[num_AMs]['overall_enc_time'].append(overall_enc_time)

    average_hdr_regen_time = hdr_regeneration_by_enc_time / len(attribute_managers_dict)
    print(
        "With the configurations: num users: {}, num attributes: {}, num_AMs: {}, the local encryption time: {:.3f}ms, enc header time: {:.3f}ms, hdr_regen time: {:.3f} = {:.3f}ms * {}, overall = {:.3f}ms".format(
            len(users_cfg_dict), num_attrs, num_AMs, local_enc_time, enc_header_gen_time, hdr_regeneration_by_enc_time, average_hdr_regen_time, len(attribute_managers_dict), overall_enc_time))


def enc_time_vs_num_users_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs, users_cfg_dict, reported_times_per_AM_dict):
    # Initialize the users with their list of attributes.
    for user_name in users_cfg_dict:
        for attr_idx in range(num_attrs):
            if random.random() > 0.5:  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}'.format(attr_idx))
    # Build the tree for each AM
    attribute_managers_dict = {}
    for am_cfg in attributes_managers_cfg_list:  # This list will contain only one element.
        am_name = am_cfg['name']
        controlled_users = am_cfg['controlled_users']
        attributes_manager = cpabe_f.AM(group_obj)
        for user_name in controlled_users:
            user_cfg = users_cfg_dict[user_name]
            assert user_cfg['associated_AM'] == am_name, \
                "The associated AM for the user does not match with the current AM name."
            for attr_name in user_cfg['attributes']:
                attributes_manager.add_attr_to_user(attr_name, user_name)
        am_cfg['obj'] = attributes_manager
        attribute_managers_dict[am_name] = attributes_manager
        # print("Users attributes list: ", attributes_manager.users_to_attrs_dict)
    ca_cpabe_ar = cpabe_f.CaCpabeAr(group_obj)
    MK, PP = ca_cpabe_ar.system_setup()
    # print("MK: ", MK)
    # print("PP: ", PP)

    # AM setup
    attributes_names_list = mabera_f.get_list_of_attr_names_controlled_by_AM(am_cfg, users_cfg_dict)

    MMK, MPK = ca_cpabe_ar.manager_setup(attributes_names_list, PP)
    # print("MMK_m: ", MMK)
    # print("MPK_m: ", MPK)

    # Generate users KEK
    UMK = {}  # A value stored privately by TA for each user.
    users_private_keys_dict = {}
    users_kek_i = {}  # Held privately by AM
    for user_name in users_cfg_dict:
        # Attribute key generation. Executed by TA.
        if user_name not in attributes_manager.users_to_attrs_dict:
            continue # This means that the user does not have any attributes.
        user_attribute_names_list = attributes_manager.users_to_attrs_dict[user_name]
        # KEK generation by AM.
        DSK, KEK = ca_cpabe_ar.key_generation(PP, MK, MPK, user_attribute_names_list, user_name, attributes_manager,
                                              UMK, users_kek_i)
        users_private_keys_dict[user_name] = {'DSK': DSK, 'KEK': KEK}
        # print("KEK for {}: {}".format(user_name, users_private_keys_dict[user_name]))

    # Encrypt the message
    rand_msg = group_obj.random(GT)
    policy_str = "att0"
    for attr_idx in range(1, num_attrs):
        policy_str += " and ATT{}".format(attr_idx)
    tic = time.time()
    CT = ca_cpabe_ar.local_encryption(policy_str, rand_msg, PP)
    local_enc_time = (time.time() - tic) * 1000
    tic = time.time()
    CT, Hdr = ca_cpabe_ar.reencryption(CT, MMK, PP, attributes_manager)
    reencrypt_time = (time.time() - tic) * 1000
    overall_time = local_enc_time + reencrypt_time
    reported_times_per_AM_dict['CA-ABE']['num_users'].append(len(users_cfg_dict))
    if 'num_attrs' in reported_times_per_AM_dict['CA-ABE']:
        reported_times_per_AM_dict['CA-ABE']['num_attrs'].append(num_attrs)
    reported_times_per_AM_dict['CA-ABE']['overall_enc_time'].append(overall_time)
    print(
        "With the configurations: num users: {}, num attributes: {}, num_AMs: 'CA-ABE', the local encryption time: {:.3f}ms, enc header time: {:.3f}ms, overall = {:.3f}ms".format(
            len(users_cfg_dict), num_attrs, local_enc_time, reencrypt_time, overall_time))


def enc_time_vs_num_users_vs_num_attrs_exp(round_id, pickle_file_path, cfg):
    print("Experiment of number of users VS number of attributes VS Enc. time")
    min_num_users = cfg['min_num_users']
    max_num_users = cfg['max_num_users']
    inc_num_users = cfg['inc_num_users']
    min_num_attrs = cfg['min_num_attrs']
    max_num_attrs = cfg['max_num_attrs']
    inc_num_attrs = cfg['inc_num_attrs']
    disable_zkp = cfg['disable_zkp']
    header_regeneration_enabled = cfg['header_regeneration_enabled']
    draw = cfg['draw']
    tic = time.time()
    number_of_AMs_to_test = cfg['number_of_AMs_to_test']
    graph_colors_list = cfg['graph_colors_list']
    labels_list = cfg['labels_list']

    group_obj = PairingGroup('SS512')
    attributes_authorities_list = [
        {
            'name': 'TA1',
            'controlled_attrs_names_list': ['ONE', 'TWO', 'THREE', 'FOUR']
        }
    ]

    mabera = mabera_f.MABERA(group_obj)
    PP = mabera.system_setup()
    # print("PP: ", PP)

    attr_authorities_pk_sk_dict = {}
    for attr_authority_dict in attributes_authorities_list:
        name = attr_authority_dict['name']
        PK_theta, SK_theta = mabera.authority_setup(name, PP)
        attr_authorities_pk_sk_dict[name] = {'PK_theta': PK_theta,
                                             'SK_theta': SK_theta}
        # print("Attribute Authority {} PK: {}, SK: {}".format(name, PK_theta, SK_theta))

    reported_times_per_AM_dict = {}
    for num_AMs in number_of_AMs_to_test:
        original_num_AMs = num_AMs
        reported_times_per_AM_dict[num_AMs] = {'num_users': [], 'num_attrs': [], 'overall_enc_time': []}

        for num_users in range(min_num_users, max_num_users, inc_num_users):
            users_cfg_dict = {}
            for i in range(num_users):
                users_cfg_dict['U' + str(i)] = {'attributes': [], 'associated_AM': 'AM1'}  # This is an initial value.
            # Assign the users to AMs
            # Initialize AMs
            attributes_managers_cfg_list = []
            if num_AMs == 'CA-ABE':
                num_AMs = 1
            for an_AM_idx in range(num_AMs):
                an_AM = {'name': "AM{}".format(an_AM_idx), 'controlled_users': []}
                for user_idx in range(an_AM_idx, num_users, num_AMs):
                    an_AM['controlled_users'].append('U{}'.format(user_idx))
                    users_cfg_dict['U{}'.format(user_idx)]['associated_AM'] = 'AM{}'.format(an_AM_idx)
                attributes_managers_cfg_list.append(an_AM)
            for num_attrs in range(min_num_attrs, max_num_attrs, inc_num_attrs): 
                if original_num_AMs == 'CA-ABE':
                    # The main purpose of the function is to change the value reported_times_per_AM_dict['CA-ABE']
                     enc_time_vs_num_users_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs,
                                                                     users_cfg_dict, reported_times_per_AM_dict)
                else:
                    # The main purpose of the function is to change the value reported_times_per_AM_dict[an_AM]
                    enc_time_vs_num_users_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                                group_obj, mabera, num_AMs, num_attrs,
                                                                reported_times_per_AM_dict, users_cfg_dict, disable_zkp=disable_zkp, header_regeneration_enabled=header_regeneration_enabled)
    
                pickle.dump(reported_times_per_AM_dict, open(pickle_file_path, 'wb'))
    if draw:
        import numpy as np
        fig = plt.figure()
        ax = plt.axes(projection='3d')
        # Data for three-dimensional scattered points
        for idx, num_AMs in enumerate(reported_times_per_AM_dict):
            xdata = np.array(reported_times_per_AM_dict[num_AMs]['num_users'])
            ydata = np.array(reported_times_per_AM_dict[num_AMs]['num_attrs'])
            zdata = np.array(reported_times_per_AM_dict[num_AMs]['overall_enc_time'])
            zdata = zdata / 1000  # Convert ms to seconds
            ax.scatter3D(xdata, ydata, zdata, c=zdata, cmap='viridis', marker='^', label='{}'.format(labels_list[idx]))
        plt.legend(loc="upper right")
        ax.set_xlabel('Num. users')
        ax.set_ylabel('Num. attributes')
        ax.set_zlabel('Overall encryption time (s)')
        plt.show(block=True)

    enc_time_vs_num_users_time = time.time() - tic
    print("Time taken to complete round {} of encryption time VS Num users experiment: {:.3f}s".format(round_id, enc_time_vs_num_users_time))
    return reported_times_per_AM_dict


if __name__ == '__main__':
    main(SIMULATION_DICT)
