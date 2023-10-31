from mabera_eval_cfg import V2V_SIMULATION_DICT
import glob
from typing import List, Tuple, Dict
# from ..schemes.abenc.mabera_bakr23 import MABERA, TreeNode, UsersBinaryTree, AM, ShnorrInteractiveZKP
import os
import sys
import time
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,hashPair
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.abspath(os.path.join(dir_path, '../schemes/abenc/')))
print(sys.path)
import mabera_bakr23 as mabera_f


def main(v2v_simulation_dict: dict):
    sim_ret_dicts_list = []
    start_simulation_run_idx = get_start_simulation_run_index(v2v_simulation_dict)
    for simulation_run_num in range(start_simulation_run_idx, v2v_simulation_dict['repeat_simulation_counter']):
        sim_ret_dict = simulation_run(V2V_SIMULATION_DICT, simulation_run_num)
        sim_ret_dicts_list.append(sim_ret_dict)

    average_sim_result_dict = get_average_results(sim_ret_dicts_list)


def simulation_run(v2v_simulation_dict: dict, simulation_run_num: int) -> Dict[str, float]:
    sim_ret_dict_mabera = simulation_run_MABERA(v2v_simulation_dict, simulation_run_num)
    sim_ret_dict_cp_abe = simulation_run_CP_ABE(v2v_simulation_dict, simulation_run_num)
    sim_ret_dict = {'MABERA': sim_ret_dict_mabera, 'CP_ABE': sim_ret_dict_cp_abe}
    return sim_ret_dict


def simulation_run_MABERA(simulation_dict: dict, simulation_run_num: int) -> Dict[str, float]:
    print("Entered simulation run for the MABERA scheme")
    group_obj = PairingGroup('SS512')
    mabera = mabera_f.MABERA(group_obj)
    tic = time.time()
    PP = mabera.system_setup()
    system_setup_time = time.time() - tic  # AB: Does not need to be recorded.
    print("Time taken to setup the system: ", system_setup_time * 1000, " ms")

    ranges_sim_dict = simulation_dict['ranges']
    for numAAs in range(ranges_sim_dict['num_AAs']['min'], ranges_sim_dict['num_AAs']['max'],
                          ranges_sim_dict['num_AAs']['inc']):


    attr_authorities_pk_sk_dict = {}
    for attr_authority_dict in attributes_authorities_list:
        name = attr_authority_dict['name']
        PK_theta, SK_theta = mabera.authority_setup(name, PP)
        attr_authorities_pk_sk_dict[name] = {'PK_theta': PK_theta,
                                             'SK_theta': SK_theta}
        print("Attribute Authority {} PK: {}, SK: {}".format(name, PK_theta, SK_theta))

def simulation_run_CP_ABE(v2v_simulation_dict: dict, simulation_run_num: int) -> Dict[str, float]:
    # TODO: AB: To be implemented.
    pass


def get_average_results(sim_ret_dicts_list: List[Dict[str, float]]) -> Dict[str, float]:
    return sim_ret_dicts_list  # AB: TODO: To be implemented


def get_start_simulation_run_index(v2v_simulation_dict: dict):
    if v2v_simulation_dict['simulation_resume']:
        saved_simulation_results_file_names = glob.glob(v2v_simulation_dict['serialized_output_folder'] + '/' +
                                                        v2v_simulation_dict['serialized_output_pattern'])
        indices = [int(file_name.split('.')[0].split('_')[-1]) for file_name in saved_simulation_results_file_names]
        simulation_run_start_idx = max(indices)
    else:
        simulation_run_start_idx = 0
    return simulation_run_start_idx


if __name__ == '__main__':
    main(V2V_SIMULATION_DICT)
