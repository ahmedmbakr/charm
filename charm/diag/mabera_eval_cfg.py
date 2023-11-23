
SIMULATION_DICT = {
    'repeat_simulation_counter': 20,  # How many times you want this simulation to be repeated then an average of the
    'simulation_resume': False,  # Whether you want the simulation to resume from the last simulation iteration
    'header_regeneration_enabled': False,  # Relaxed encryption means that the header re-encryption will not be executed because the AMs are assumed to be honest and that they will not collude with the users.
    # results is reported
    'serialization_paths': {
        'serialized_output_folder': 'diag_output'  # The path is relative to this file.
    },
    'enc_dec_time_vs_num_attrs_exp': {
        # In this experiment, the number of users is fixed. We want to test the effect of changing the number of
        # attributes over time.
        'enabled': False,
        'draw': False,
        'disable_zkp': True,
        'header_regeneration_enabled': False,
        'reported_times_per_AM_dict_pickle_path': './diag_output/reported_enc_dec_time_vs_num_attrs_pickle_{}.p',
        'total_num_users': 1000,
        'min_num_attrs': 1,
        'max_num_attrs': 51,
        'inc_num_attrs': 10,
        'number_of_AMs_to_test': ['CA-ABE', 5, 10, 20],
        'graph_colors_list': ['r.-', 'bx-.', 'g<--', 'c>-.'],
        'labels_list': ['CA-ABE', 'Our scheme with 5 AMs', 'Our scheme with 10 AMs', 'Our scheme with 20 AMs'],
    },
    'enc_time_vs_num_users_exp': {
        # In this experiment, the number of attributes is fixed. We want to test the effect of changing the number of
        # users over time.
        'enabled': False,
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
        'header_regeneration_enabled': False
    },
    'enc_time_vs_num_users_vs_num_attrs_exp_cfg': {
        # In this experiment, we want to test the effect of changing the number of users and attributes over time.
        'enabled': False,
        'reported_enc_time_vs_num_users_vs_num_attrs_pickle_path': './diag_output/reported_enc_time_vs_num_users_vs_num_attrs_pickle_{}.p',
        'min_num_attrs': 1,
        'max_num_attrs': 51,
        'inc_num_attrs': 10,
        'min_num_users': 100,
        'max_num_users': 1001,
        'inc_num_users': 100,
        'number_of_AMs_to_test': ['CA-ABE', 5, 10, 20],
        'graph_colors_list': ['r', 'b', 'g', 'c'],
        'labels_list': ['CA-ABE', 'Our scheme with 5 AMs', 'Our scheme with 10 AMs', 'Our scheme with 20 AMs'],
        'draw': False,
        'disable_zkp': True,
        'header_regeneration_enabled': True
    },
    'report_all_algorithm_times_exp_cfg': {
        # In this experiment, we want to test the effect of changing the number of users and attributes over time.
        'enabled': True,
        'reported_all_algorithm_times_pickle_path': './diag_output/reported_all_algorithm_times_pickle_{}.p',
        'total_num_attrs': 5,
        'total_num_users': 100,
        'number_of_AMs_to_test': ['CA-ABE', 10],
        'graph_colors_list': ['r', 'b', 'g', 'c'],
        'labels_list': ['CA-ABE', 'Our scheme with 10 trusted AMs', 'Our scheme with 10 semi-trusted AMs', 'Our scheme with 10 malicious AMs'],
        'draw': False
    },
}
