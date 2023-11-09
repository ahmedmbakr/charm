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


def enc_dec_time_vs_num_attrs_exp(round_id, reported_times_per_AM_dict_pickle_path, cfg):
    print("Experiment of number of attributes VS encryption time")
    total_num_users = cfg['total_num_users']
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
        reported_times_per_AM_dict[num_AMs] = {'num_attrs': [], 'overall_enc_time': [], 'overall_dec_time': []}
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

        for num_attrs in range(min_num_attrs, max_num_attrs, inc_num_attrs):
            if original_num_AMs == 'CA-ABE':
                # The main purpose of the function is to change the value reported_times_per_AM_dict['CA-ABE']
                 enc_dec_time_vs_num_attrs_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs,
                                                                 users_cfg_dict, reported_times_per_AM_dict)
            else:
                # The main purpose of the function is to change the value reported_times_per_AM_dict[an_AM]
                enc_dec_time_vs_num_attrs_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                                group_obj, mabera, num_AMs, num_attrs,
                                                                reported_times_per_AM_dict, users_cfg_dict, disable_zkp=disable_zkp, header_regeneration_enabled=header_regeneration_enabled)
            pickle.dump(reported_times_per_AM_dict, open(reported_times_per_AM_dict_pickle_path, 'wb'))
    if draw:
        fig = plt.figure()
        # Draw the encryption graph.
        ax = plt.subplot(1, 2, 1)
        plt.xlabel('Num. attributes')
        plt.ylabel('Enc. Time (ms)')
        for idx, num_AMs in enumerate(reported_times_per_AM_dict):
            plt.plot(reported_times_per_AM_dict[num_AMs]['num_attrs'], reported_times_per_AM_dict[num_AMs]['overall_enc_time'], '{}'.format(graph_colors_list[idx]),
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

    enc_time_vs_num_attrs_time = time.time() - tic
    print("Time taken to complete round {} of encryption time VS Num attributes experiment: {:.3f}s".format(round_id, enc_time_vs_num_attrs_time))
    return reported_times_per_AM_dict


def enc_dec_time_vs_num_attrs_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs, users_cfg_dict, reported_times_per_AM_dict):
    # Initialize the users with their list of attributes.
    for user_idx, user_name in enumerate(users_cfg_dict):
        for attr_idx in range(num_attrs):
            if (user_idx == 0  # U0 has all the attributes to ease the calculation of the decryption later
                    or random.random() > 0.5):  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}'.format(attr_idx))
        if user_idx == 0:
            dec_user_name = user_name  # Save the name of the user who will be able to decrypt.
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
        break  # AB: It is enough to generate the keys for only the first user, since he is the one who will decrypt.

    # Encrypt the message
    rand_msg = group_obj.random(GT)
    policy_str = "ATT0"
    for attr_idx in range(1, num_attrs):
        policy_str += " and ATT{}".format(attr_idx)
    tic = time.time()
    CT = ca_cpabe_ar.local_encryption(policy_str, rand_msg, PP)
    local_enc_time = (time.time() - tic) * 1000
    tic = time.time()
    CT, Hdr = ca_cpabe_ar.reencryption(CT, MMK, PP, attributes_manager)
    reencrypt_time = (time.time() - tic) * 1000
    overall_time = local_enc_time + reencrypt_time

    user_private_keys_dict = users_private_keys_dict[dec_user_name]
    DSK = user_private_keys_dict['DSK']
    KEK = user_private_keys_dict['KEK']
    tic = time.time()
    recovered_M = ca_cpabe_ar.decrypt(PP, CT, Hdr, DSK, KEK, dec_user_name, attributes_manager)
    local_dec_time = (time.time() - tic) * 1000
    # print('Recovered Message: ', recovered_M)
    assert rand_msg == recovered_M, "FAILED Decryption: message is incorrect"

    reported_times_per_AM_dict['CA-ABE']['num_attrs'].append(num_attrs)
    reported_times_per_AM_dict['CA-ABE']['overall_enc_time'].append(overall_time)
    reported_times_per_AM_dict['CA-ABE']['overall_dec_time'].append(local_dec_time)
    print(
        "With the configurations: num atts: {}, num_AMs: 'CA-ABE', the local enc time: {:.3f}ms, enc header time: {:.3f}ms, overall enc. time = {:.3f}ms, dec. time = {:.3f}ms".format(
            num_attrs, local_enc_time, reencrypt_time, overall_time, local_dec_time))


def enc_dec_time_vs_num_attrs_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                    group_obj, mabera, num_AMs, num_attrs, reported_times_per_AM_dict,
                                                    users_cfg_dict, disable_zkp=False, header_regeneration_enabled=False):
    # Initialize the users with their list of attributes.
    for user_idx, user_name in enumerate(users_cfg_dict):
        for attr_idx in range(num_attrs):
            if (user_idx == 0  # U0 has all the attributes to ease the calculation of the decryption later
                    or random.random() > 0.5):  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}@TA1'.format(attr_idx))
        if user_idx == 0:
            dec_user_name = user_name  # The user who has the required attributes to perform the decryption.
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
        break  # AB: It is enough to generate the keys for only the first user, since he is the one who will decrypt.

    # Encrypt the message.
    policy = "ATT0@TA1"
    for attr_idx in range(1, num_attrs):
        policy += " and ATT{}@TA1".format(attr_idx)
    M = group_obj.random(GT)  # Random message
    attributes_issuer_pks = mabera_f.get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    tic = time.time()
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP, header_regeneration_enabled=header_regeneration_enabled)
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

    a_user_cfg = users_cfg_dict[dec_user_name]
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    tic = time.time()
    dec_msg = mabera.decrypt(PP, CT, Hdr_m_dict[associated_AM_name], users_secret_keys[dec_user_name], dec_user_name, dec_user_name, am)
    local_dec_time = (time.time() - tic) * 1000
    # print("Decrypted Message: ", dec_msg)
    assert M == dec_msg, "FAILED Decryption: message is incorrect"

    reported_times_per_AM_dict[num_AMs]['num_attrs'].append(num_attrs)
    reported_times_per_AM_dict[num_AMs]['overall_enc_time'].append(overall_enc_time)
    reported_times_per_AM_dict[num_AMs]['overall_dec_time'].append(local_dec_time)
    average_hdr_regen_time = hdr_regeneration_by_enc_time / len(attribute_managers_dict)
    print(
        "With the configurations: num atts: {}, num_AMs: {}, the local encryption time: {:.3f}ms, enc header time: {:.3f}ms, hdr_regen time: {:.3f} = {:.3f}ms * {}, overall enc. = {:.3f}ms, local dec. = {:.3f}ms".format(
            num_attrs, num_AMs, local_enc_time, enc_header_gen_time, hdr_regeneration_by_enc_time,
            average_hdr_regen_time, len(attribute_managers_dict), overall_enc_time, local_dec_time))


def main(simulation_dict):
    print("Current configurations: {}".format(simulation_dict))
    header_regeneration_enabled = simulation_dict['header_regeneration_enabled']
    enc_dec_time_vs_num_attrs_exp_cfg = simulation_dict['enc_dec_time_vs_num_attrs_exp']
    enc_time_vs_num_users_exp_cfg = simulation_dict['enc_time_vs_num_users_exp']
    enc_time_vs_num_users_vs_num_attrs_exp_cfg = simulation_dict['enc_time_vs_num_users_vs_num_attrs_exp_cfg']
    all_algos_times_exp_cfg = simulation_dict['report_all_algorithm_times_exp_cfg']
    
    enc_dec_reported_times_per_AM_pickle_path = enc_dec_time_vs_num_attrs_exp_cfg['reported_times_per_AM_dict_pickle_path']
    enc_dec_reported_times_per_AM_pickle_path = os.path.abspath(enc_dec_reported_times_per_AM_pickle_path)
    
    reported_enc_time_vs_num_users_pickle_path = enc_time_vs_num_users_exp_cfg['reported_enc_time_vs_num_users_pickle_path']
    reported_enc_time_vs_num_users_pickle_path = os.path.abspath(reported_enc_time_vs_num_users_pickle_path)

    reported_enc_time_vs_num_users_vs_num_attrs_pickle_path = enc_time_vs_num_users_vs_num_attrs_exp_cfg[
        'reported_enc_time_vs_num_users_vs_num_attrs_pickle_path']
    reported_enc_time_vs_num_users_vs_num_attrs_pickle_path = os.path.abspath(reported_enc_time_vs_num_users_vs_num_attrs_pickle_path)

    reported_all_algorithm_times_pickle_path = all_algos_times_exp_cfg[
        'reported_all_algorithm_times_pickle_path']
    reported_all_algorithm_times_pickle_path = os.path.abspath(reported_all_algorithm_times_pickle_path)

    repeat_simulation_counter = simulation_dict['repeat_simulation_counter']
    list_enc_dec_time_vs_num_attrs_dict = []
    list_enc_time_vs_num_users_dict = []
    list_enc_time_vs_num_users_vs_num_attrs_dict = []
    list_all_algos_times_dict = []
    for i in range(repeat_simulation_counter):
        print("Simulation round: {}".format(i))
        if enc_dec_time_vs_num_attrs_exp_cfg['enabled']:
            enc_dec_time_vs_num_attrs_dict = enc_dec_time_vs_num_attrs_exp(i, enc_dec_reported_times_per_AM_pickle_path.format(i),
                                                                       enc_dec_time_vs_num_attrs_exp_cfg)
            list_enc_dec_time_vs_num_attrs_dict.append(enc_dec_time_vs_num_attrs_dict)

        if enc_time_vs_num_users_exp_cfg['enabled']:
            enc_time_vs_num_users_dict = enc_time_vs_num_users_exp(i, reported_enc_time_vs_num_users_pickle_path.format(i),
                                                                   enc_time_vs_num_users_exp_cfg, header_regeneration_enabled=header_regeneration_enabled)
            list_enc_time_vs_num_users_dict.append(enc_time_vs_num_users_dict)
            
        if enc_time_vs_num_users_vs_num_attrs_exp_cfg['enabled']:
            enc_time_vs_num_users_vs_num_attrs_dict = enc_time_vs_num_users_vs_num_attrs_exp(i,
                                                                   reported_enc_time_vs_num_users_vs_num_attrs_pickle_path.format(i),
                                                                   enc_time_vs_num_users_vs_num_attrs_exp_cfg)
            list_enc_time_vs_num_users_vs_num_attrs_dict.append(enc_time_vs_num_users_vs_num_attrs_dict)
            
        if all_algos_times_exp_cfg['enabled']:
            all_algos_times_dict = all_algos_times_exp(i,
                                                reported_all_algorithm_times_pickle_path.format(i),
                                                all_algos_times_exp_cfg)
            list_all_algos_times_dict.append(all_algos_times_dict)

    # print(enc_dec_time_vs_num_attrs_dict)


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

    # Commented because it is not needed for the calculation of time, which will save time.
    # # Generate users secret keys
    # users_secret_keys = {}
    # for a_user_name, a_user_cfg in users_cfg_dict.items():
    #     UID = a_user_name
    #     attributes_dict = mabera_f.get_attributes_categorized_by_AI_dict(a_user_cfg['attributes'])  # AI name is the key
    #     associated_AM_name = a_user_cfg['associated_AM']
    #     MPK_m = attr_managers_pk_sk_dict[associated_AM_name]['MPK_m']
    #     DSK_i = {'D_u_dict': {}, 'D_u_dash_dict': {}}
    #     kek_init = {}
    #     g_gamma, gamma_i = mabera.attribute_key_gen_user_part(PP['g'])
    #
    #     for AI_name, attrs_list_by_AI in attributes_dict.items():
    #         SK_theta = attr_authorities_pk_sk_dict[AI_name]['SK_theta']
    #         DSK_i_theta, kek_theta = mabera.attribute_key_gen(attrs_list_by_AI, SK_theta, UID, MPK_m, PP,
    #                                                           g_gamma, gamma_i)
    #         kek_init.update(kek_theta)
    #         DSK_i['D_u_dict'].update(DSK_i_theta['D_u_dict'])
    #         DSK_i['D_u_dash_dict'].update(DSK_i_theta['D_u_dash_dict'])
    #
    #     AM_obj = attribute_managers_dict[associated_AM_name]
    #     KEK_i = mabera.user_attributes_kek_generation(kek_init, AM_obj, a_user_cfg['attributes'], a_user_name)
    #
    #     users_secret_keys[a_user_name] = {'DSK_i': DSK_i, 'KEK_i': KEK_i, 'gamma_i': gamma_i}
    #     # print("DSK for user {}: {}".format(a_user_name, users_secret_keys[a_user_name]))

    # Encrypt the message.
    policy = "ATT0@TA1"
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

    # Commented because it is not needed for the calculation of time, which will save time.
    # # Generate users KEK
    # UMK = {}  # A value stored privately by TA for each user.
    # users_private_keys_dict = {}
    # users_kek_i = {}  # Held privately by AM
    # for user_name in users_cfg_dict:
    #     # Attribute key generation. Executed by TA.
    #     if user_name not in attributes_manager.users_to_attrs_dict:
    #         continue # This means that the user does not have any attributes.
    #     user_attribute_names_list = attributes_manager.users_to_attrs_dict[user_name]
    #     # KEK generation by AM.
    #     DSK, KEK = ca_cpabe_ar.key_generation(PP, MK, MPK, user_attribute_names_list, user_name, attributes_manager,
    #                                           UMK, users_kek_i)
    #     users_private_keys_dict[user_name] = {'DSK': DSK, 'KEK': KEK}
    #     # print("KEK for {}: {}".format(user_name, users_private_keys_dict[user_name]))

    # Encrypt the message
    rand_msg = group_obj.random(GT)
    policy_str = "ATT0"
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
        import matplotlib as mpl
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
        ax.legend(fake_lines, labels_list, numpoints=1)
        # Add a legend to the figure
        # plt.legend(loc="upper right")
        ax.set_xlabel('Num. users')
        ax.set_ylabel('Num. attributes')
        ax.set_zlabel('Overall encryption time (s)')
        # ax.invert_xaxis()
        plt.show(block=True)

    enc_time_vs_num_users_time = time.time() - tic
    print("Time taken to complete round {} of encryption time VS Num users experiment: {:.3f}s".format(round_id, enc_time_vs_num_users_time))
    return reported_times_per_AM_dict


def all_algos_times_exp(round_id, pickle_file_path, cfg, header_regeneration_enabled=True):
    print("Experiment of all algorithms run time")
    total_num_attrs = cfg['total_num_attrs']
    total_num_users = cfg['total_num_users']
    disable_zkp = cfg['disable_zkp']
    draw = cfg['draw']
    tic = time.time()
    number_of_AMs_to_test = cfg['number_of_AMs_to_test']
    graph_colors_list = cfg['graph_colors_list']
    labels_list = cfg['labels_list']

    group_obj = PairingGroup('SS512')

    ca_abe_reported_times_dict = {}
    attributes_authorities_list = [
        {
            'name': 'TA1',
        }
    ]
    mabera_reported_times_dict = {}

    mabera = mabera_f.MABERA(group_obj)
    PP = mabera.system_setup()
    # print("PP: ", PP)

    attr_authorities_pk_sk_dict = {}
    for attr_authority_dict in attributes_authorities_list:
        name = attr_authority_dict['name']
        tic = time.time()
        PK_theta, SK_theta = mabera.authority_setup(name, PP)
        local_authority_setup_time = (time.time() - tic) * 1000
        mabera_reported_times_dict['auth_setup_time'] = local_authority_setup_time
        attr_authorities_pk_sk_dict[name] = {'PK_theta': PK_theta,
                                             'SK_theta': SK_theta}
        # print("Attribute Authority {} PK: {}, SK: {}".format(name, PK_theta, SK_theta))

    reported_times_per_AM_dict = {}
    for num_AMs in number_of_AMs_to_test:
        original_num_AMs = num_AMs
        reported_times_per_AM_dict[num_AMs] = {'num_users': [], 'overall_enc_time': []}

        num_users = total_num_users
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
             all_algos_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, total_num_attrs,
                                                             users_cfg_dict, ca_abe_reported_times_dict)
        else:
            # The main purpose of the function is to change the value reported_times_per_AM_dict[an_AM]
            all_algos_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                        group_obj, mabera, num_AMs, total_num_attrs,
                                                        mabera_reported_times_dict, users_cfg_dict, disable_zkp=disable_zkp, header_regeneration_enabled=header_regeneration_enabled)

            pickle.dump({'CA-ABE': ca_abe_reported_times_dict , 'MABERA': mabera_reported_times_dict}, open(pickle_file_path, 'wb'))
    if draw:
        import pandas as pd
        plotdata = pd.DataFrame({
            labels_list[0]: [ca_abe_reported_times_dict['auth_setup_time'],
                             ca_abe_reported_times_dict['manager_setup_time'],
                             ca_abe_reported_times_dict['key_gen_time'],
                             ca_abe_reported_times_dict['dec_time']],
            labels_list[1]: [mabera_reported_times_dict['auth_setup_time'],
                             mabera_reported_times_dict['manager_setup_time'],
                             mabera_reported_times_dict['key_gen_time'],
                             mabera_reported_times_dict['dec_time']]
        }, index=['auth_setup', 'manager_setup', 'key_gen', 'dec'])

        plotdata.plot(kind="barh", figsize=(15, 8), color=graph_colors_list)
        plt.title('Algorithms execution times when num users={}, num attrs={}'.format(total_num_users, total_num_attrs))
        plt.xlabel("Algorithms")
        plt.ylabel("Execution time (ms)")
        plt.show(block=True)

    enc_time_vs_num_users_time = time.time() - tic
    print("Time taken to complete round {} of encryption time VS Num users experiment: {:.3f}s".format(round_id, enc_time_vs_num_users_time))
    return reported_times_per_AM_dict


def all_algos_single_cfg_run_CP_ABE(attributes_managers_cfg_list, group_obj, num_attrs, users_cfg_dict, reported_times_dict):
    # Initialize the users with their list of attributes.
    for user_idx, user_name in enumerate(users_cfg_dict):
        for attr_idx in range(num_attrs):
            if (user_idx == 0  # U0 has all the attributes to ease the calculation of the decryption later
                    or random.random() > 0.5):  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}'.format(attr_idx))
        if user_idx == 0:
            dec_user_name = user_name  # Save the name of the user who will be able to decrypt.
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
    tic = time.time()
    MK, PP = ca_cpabe_ar.system_setup()
    reported_times_dict['auth_setup_time'] = (time.time() - tic) * 1000
    # print("MK: ", MK)
    # print("PP: ", PP)

    # AM setup
    attributes_names_list = mabera_f.get_list_of_attr_names_controlled_by_AM(am_cfg, users_cfg_dict)

    tic = time.time()
    MMK, MPK = ca_cpabe_ar.manager_setup(attributes_names_list, PP)
    reported_times_dict['manager_setup_time'] = (time.time() - tic) * 1000
    # print("MMK_m: ", MMK)
    # print("MPK_m: ", MPK)

    # Generate users KEK
    UMK = {}  # A value stored privately by TA for each user.
    users_private_keys_dict = {}
    users_kek_i = {}  # Held privately by AM
    for user_name in users_cfg_dict:
        # Attribute key generation. Executed by TA.
        if user_name not in attributes_manager.users_to_attrs_dict:
            continue  # This means that the user does not have any attributes.
        user_attribute_names_list = attributes_manager.users_to_attrs_dict[user_name]
        # KEK generation by AM.
        tic = time.time()
        DSK, KEK = ca_cpabe_ar.key_generation(PP, MK, MPK, user_attribute_names_list, user_name, attributes_manager,
                                              UMK, users_kek_i)
        toc = time.time()
        users_private_keys_dict[user_name] = {'DSK': DSK, 'KEK': KEK}
        if 'key_gen_time' not in reported_times_dict:
            reported_times_dict['key_gen_time'] = (toc - tic) * 1000
            break
        # print("KEK for {}: {}".format(user_name, users_private_keys_dict[user_name]))

    # Encrypt the message
    rand_msg = group_obj.random(GT)
    policy_str = "ATT0"
    for attr_idx in range(1, num_attrs):
        policy_str += " and ATT{}".format(attr_idx)
    tic = time.time()
    CT = ca_cpabe_ar.local_encryption(policy_str, rand_msg, PP)
    local_enc_time = (time.time() - tic) * 1000
    tic = time.time()
    CT, Hdr = ca_cpabe_ar.reencryption(CT, MMK, PP, attributes_manager)
    reencrypt_time = (time.time() - tic) * 1000
    overall_enc_time = local_enc_time + reencrypt_time
    reported_times_dict['enc_time'] = overall_enc_time

    user_private_keys_dict = users_private_keys_dict[dec_user_name]
    DSK = user_private_keys_dict['DSK']
    KEK = user_private_keys_dict['KEK']
    tic = time.time()
    recovered_M = ca_cpabe_ar.decrypt(PP, CT, Hdr, DSK, KEK, dec_user_name, attributes_manager)
    local_dec_time = (time.time() - tic) * 1000
    reported_times_dict['dec_time'] = local_dec_time
    # print('Recovered Message: ', recovered_M)
    assert rand_msg == recovered_M, "FAILED Decryption: message is incorrect"

    print(
        "With the configurations: num atts: {}, num_AMs: 'CA-ABE', num_users: {}, all algorithms times: {}".format(
            num_attrs, len(users_cfg_dict), reported_times_dict))


def all_algos_single_cfg_run_MABERA(PP, attr_authorities_pk_sk_dict, attributes_managers_cfg_list,
                                                    group_obj, mabera, num_AMs, num_attrs, reported_times_dict,
                                                    users_cfg_dict, disable_zkp=False, header_regeneration_enabled=False):
    # Initialize the users with their list of attributes.
    for user_idx, user_name in enumerate(users_cfg_dict):
        for attr_idx in range(num_attrs):
            if (user_idx == 0  # U0 has all the attributes to ease the calculation of the decryption later
                    or random.random() > 0.5):  # Toss of a coin if this user have this attribute or not.
                users_cfg_dict[user_name]['attributes'].append('ATT{}@TA1'.format(attr_idx))
        if user_idx == 0:
            dec_user_name = user_name  # The user who has the required attributes to perform the decryption.
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

        tic = time.time()
        MMK_m, MPK_m = mabera.manager_setup(attributes_names_list, PP)
        reported_times_dict['manager_setup_time'] = (time.time() - tic) * 1000
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
        tic = time.time()
        g_gamma, gamma_i = mabera.attribute_key_gen_user_part(PP['g'])
        user_key_gen_part_time = (time.time() - tic) * 1000

        for AI_name, attrs_list_by_AI in attributes_dict.items():
            SK_theta = attr_authorities_pk_sk_dict[AI_name]['SK_theta']
            tic = time.time()
            DSK_i_theta, kek_theta = mabera.attribute_key_gen(attrs_list_by_AI, SK_theta, UID, MPK_m, PP,
                                                              g_gamma, gamma_i)
            auth_key_gen_part_time = (time.time() - tic) * 1000
            kek_init.update(kek_theta)
            DSK_i['D_u_dict'].update(DSK_i_theta['D_u_dict'])
            DSK_i['D_u_dash_dict'].update(DSK_i_theta['D_u_dash_dict'])

        AM_obj = attribute_managers_dict[associated_AM_name]
        tic = time.time()
        KEK_i = mabera.user_attributes_kek_generation(kek_init, AM_obj, a_user_cfg['attributes'], a_user_name)
        am_key_gen_part_time = (time.time() - tic) * 1000

        key_gen_overall_time = user_key_gen_part_time + auth_key_gen_part_time + am_key_gen_part_time
        users_secret_keys[a_user_name] = {'DSK_i': DSK_i, 'KEK_i': KEK_i, 'gamma_i': gamma_i}
        # print("DSK for user {}: {}".format(a_user_name, users_secret_keys[a_user_name]))
        if 'key_gen_time' not in reported_times_dict:
            reported_times_dict['key_gen_time'] = key_gen_overall_time
            break  # A hack as we only need the first user.

    # Encrypt the message.
    policy = "ATT0@TA1"
    for attr_idx in range(1, num_attrs):
        policy += " and ATT{}@TA1".format(attr_idx)
    M = group_obj.random(GT)  # Random message
    attributes_issuer_pks = mabera_f.get_authorities_public_keys_dict(attr_authorities_pk_sk_dict)
    tic = time.time()
    CT, K_dash, a_xs_dict = mabera.local_encryption(policy, M, attributes_issuer_pks, PP,
                                                    header_regeneration_enabled=header_regeneration_enabled)
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
        Hdr_m_dict[an_AM_name] = mabera.generate_ciphertext_headers_by_AM(K_dash, MMK_m, am, PP,
                                                                          zkp_enabled=disable_zkp)
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
    reported_times_dict['enc_time'] = overall_enc_time

    a_user_cfg = users_cfg_dict[dec_user_name]
    associated_AM_name = a_user_cfg['associated_AM']
    am = attribute_managers_dict[associated_AM_name]
    tic = time.time()
    dec_msg = mabera.decrypt(PP, CT, Hdr_m_dict[associated_AM_name], users_secret_keys[dec_user_name], dec_user_name,
                             dec_user_name, am)
    local_dec_time = (time.time() - tic) * 1000
    # print("Decrypted Message: ", dec_msg)
    assert M == dec_msg, "FAILED Decryption: message is incorrect"
    reported_times_dict['dec_time'] = local_dec_time

    average_hdr_regen_time = hdr_regeneration_by_enc_time / len(attribute_managers_dict)
    print(
        "With the configurations: num atts: {}, num_AMs: {}, num_users: {}, all algorithms times: {}".format(
            num_attrs, len(attribute_managers_dict), len(users_cfg_dict), reported_times_dict))


if __name__ == '__main__':
    main(SIMULATION_DICT)
