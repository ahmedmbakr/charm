
SIMULATION_DICT = {
    'repeat_simulation_counter': 2,  # How many times you want this simulation to be repeated then an average of the
    'simulation_resume': False,  # Whether you want the simulation to resume from the last simulation iteration
    'header_regeneration_enabled': True,  # Relaxed encryption means that the header re-encryption will not be executed because the AMs are assumed to be honest and that they will not collude with the users.
    # results is reported
    'serialization_paths': {
        'serialized_output_folder': 'diag_output'  # The path is relative to this file.
    },
    'enc_time_vs_num_attrs_exp': {
        # In this experiment, the number of users is fixed. We want to test the effect of changing the number of
        # attributes over time.
        'enabled': True,
        'draw': False,
        'disable_zkp': True,
        'reported_times_per_AM_dict_pickle_path': './diag_output/reported_times_per_AM_dict_pickle_{}.p',
        'total_num_users': 100,
        'min_num_attrs_per_user': 1,
        'max_num_attrs_per_user': 20,
        'inc_num_attrs_per_user': 10,
        'number_of_AMs_to_test': ['CA-ABE', 1, 10, 20],
        'graph_colors_list': ['r', 'b', 'g', 'c'],
        'labels_list': ['CA-ABE', 'Our scheme with 1 AMs', 'Our scheme with 10 AMs', 'Our scheme with 20 AMs']
    },
    'enc_time_vs_num_users_exp': {
        # In this experiment, the number of attributes is fixed. We want to test the effect of changing the number of
        # users over time.
        'enabled': True,
        'reported_enc_time_vs_num_users_pickle_path': './diag_output/reported_enc_time_vs_num_users_pickle_{}.p',
        'total_num_attrs': 5,
        'min_num_users': 100,
        'max_num_users': 1001,
        'inc_num_users': 100,
        'number_of_AMs_to_test': ['CA-ABE', 1, 10, 20],
        'graph_colors_list': ['r', 'b', 'g', 'c'],
        'labels_list': ['CA-ABE', 'Our scheme with 1 AMs', 'Our scheme with 10 AMs', 'Our scheme with 20 AMs'],
        'draw': True,
        'disable_zkp': True,
    },
    'ranges': {
        'num_AAs': {  # Num attribute authorities
            'min': 1,
            'max': 100,
            'inc': 10
        }
    },
    'defaults': {
        'AA_cfgs': {  # Attribute Authority configuration
                'name': 'TA1',
                'controlled_attrs_names_list': ['ONE', 'TWO', 'THREE', 'FOUR']
        },
        'AM_cfgs': {
                'name': 'AM1',
                'controlled_users': ['U1', 'U2', 'U3', 'U4', 'U5', 'U6', 'U7', 'U8']
        },
        'users_cfg_dict': {
            'U1': {
                'attributes': ['ONE@TA1', 'FOUR@TA1', 'TWO@TA1', 'SIX@TA2'],
                'associated_AM': 'AM1'
            }
        }
    }
}
