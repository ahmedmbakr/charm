
SIMULATION_DICT = {
    'repeat_simulation_counter': 1,  # How many times you want this simulation to be repeated then an average of the
    'simulation_resume': False,  # Whether you want the simulation to resume from the last simulation iteration
    # results is reported
    'serialization_paths': {
        'reported_times_per_AM_dict_pickle_path': './diag_output/reported_times_per_AM_dict_pickle_path.p',
        'serialized_output_folder': 'diag_output'  # The path is relative to this file.
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
