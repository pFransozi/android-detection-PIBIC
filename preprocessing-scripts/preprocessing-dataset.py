import sys
import getopt
import os
import pandas as pd

# python preprocessing-dataset.py --input-goodware-batch-dir=./andropytool_output/goodware_batch/ --input-malware-batch-dir=./andropytool_output/malware_batch/ --input-goodware-dir=./andropytool_output/goodware_itens/ --input-malware-dir=./andropytool_output/malware_itens --output-dataframe-file=./csv/

GOODWARE_CLASS = 0
MALWARE_CLASS = 1
BATCH = 1
ITENS = 0


def debug(msg):
    print(msg)


def preprocessing_dataframes_save_to_cvs(output_cvs, dframes):
    dfs_opcodes = pd.DataFrame()
    dfs_apicalls = pd.DataFrame()
    dfs_permissions = pd.DataFrame()

    for dframe, class_df in dframes:

        opcodes = dframe["Opcodes"]
        apicalls = dframe["API calls"]
        permission_dict = {
            permission: 1 for permission in dframe["Permissions"]}

        dfs_tmp = pd.DataFrame(opcodes, index=[0])
        dfs_tmp["class"] = class_df
        dfs_opcodes = pd.concat([dfs_opcodes, dfs_tmp])

        dfs_tmp = pd.DataFrame(apicalls, index=[0])
        dfs_tmp["class"] = class_df
        dfs_apicalls = pd.concat([dfs_apicalls, dfs_tmp])

        dfs_tmp = pd.DataFrame(permission_dict, index=[0])
        dfs_tmp["class"] = class_df
        dfs_permissions = pd.concat([dfs_permissions, dfs_tmp])

    dfs_opcodes.fillna(0, inplace=True)
    dfs_opcodes.to_csv(os.path.join(output_cvs, "opcodes.csv"))

    dfs_apicalls.fillna(0, inplace=True)
    dfs_apicalls.to_csv(os.path.join(output_cvs, "apicalls.csv"))

    dfs_permissions.fillna(0, inplace=True)
    dfs_permissions.to_csv(os.path.join(output_cvs, "permissions.csv"))


def load_json_malware(input_dir):
    return load_json(input_dir, MALWARE_CLASS, ITENS)


def load_json_goodware(input_dir):
    return load_json(input_dir, GOODWARE_CLASS, ITENS)


def load_json_malware_batch(input_dir):
    return load_json(input_dir, MALWARE_CLASS, BATCH)


def load_json_goodware_batch(input_dir):
    return load_json(input_dir, GOODWARE_CLASS, BATCH)


def load_json(input_dir, classification, batch):
    dframes = []
    pd_json_tmp = pd.DataFrame()

    with os.scandir(input_dir) as entries:
        for entry in entries:
            if entry.is_file() and entry.name.endswith('json'):
                pd_json = pd.read_json(entry.path)

                if batch == BATCH:
                    for col_apk in pd_json.columns:
                        pd_json_tmp = pd_json[col_apk]["Static_analysis"]
                        dframes.append((pd_json_tmp, classification))
                else:
                    dframes.append((pd_json["Static_analysis"].to_frame()["Static_analysis"], classification))

    if len(dframes) == 0:
        print(
            f'No json file found: directory {input_dir}')

    return dframes


def is_to_drop(col_name):
    return not (col_name.startswith('Permissions')
                or col_name.startswith('Opcodes')
                or col_name.startswith('API calls'))


def get_dirs_from_args(argv):
    input_goodware_dir = ''
    input_malware_dir = ''
    input_goodware_batch_dir = ''
    input_malware_batch_dir = ''
    output_cvs = ''

    # # python preprocessing-dataset.py
    # --input-goodware-batch-dir=./andropytool_output/goodware_batch/
# --input-malware-batch-dir=./andropytool_output/malware_batch/
# --input-goodware-dir=./andropytool_output/goodware_itens/
# --input-malware-dir=./andropytool_output/malware_itens --output-dataframe-file=./csv/

    opts, args = getopt.getopt(argv, ['h'], [
                               "input-goodware-dir=",
                               "input-malware-dir=",
                               "input-goodware-batch-dir=",
                               "input-malware-batch-dir=",
                               "output-dataframe-file="])

    for opt, arg in opts:
        if opt == '-h':
            print('preprocessing-dataset.py --input-goodware-dir=<dir> --input-malware-dir=<dir> --input-goodware-batch-dir=<dir> --input-malware-batch-dir=<dir> --output-dataframe-file=<file>')
            sys.exit(-1)
        elif opt in ("--input-goodware-dir"):
            input_goodware_dir = arg
        elif opt in ("--input-malware-dir"):
            input_malware_dir = arg
        elif opt in ("--input-goodware-batch-dir"):
            input_goodware_batch_dir = arg
        elif opt in ("--input-malware-batch-dir"):
            input_malware_batch_dir = arg
        elif opt in ("--output-dataframe-file"):
            output_cvs = arg

    return (input_goodware_dir, input_malware_dir, input_goodware_batch_dir, input_malware_batch_dir, output_cvs)


def validate_dirs(input_malware_dir, input_goodware_dir, input_malware_batch_dir, input_goodware_batch_dir, output_cvs):

    error_message = ''

    if (not os.path.isdir(input_malware_dir)):
        error_message.join(f"Invalid malware directory ({input_malware_dir})")

    if (not os.path.isdir(input_goodware_dir)):
        error_message.join(
            f"Invalid goodware directory ({input_goodware_dir})")

    if (not os.path.isdir(input_malware_batch_dir)):
        error_message.join(f"Invalid malware directory ({input_malware_dir})")

    if (not os.path.isdir(input_goodware_batch_dir)):
        error_message.join(
            f"Invalid goodware directory ({input_goodware_dir})")

    if (not os.path.isdir(output_cvs)):
        error_message.join(f"Invalid output directory ({output_cvs})")

    return error_message


def main(argv):

    debug("Starting preprocessing dataframes from json to cvs.")

    input_malware_itens_dir = ''
    input_goodware_itens_dir = ''
    input_malware_batch_dir = ''
    input_goodware_batch_dir = ''
    output_cvs = ''

    debug("Validating working directories.")

    input_goodware_itens_dir, input_malware_itens_dir, input_goodware_batch_dir, input_malware_batch_dir, output_cvs = get_dirs_from_args(
        argv)

    debug("Directories:")
    debug(f"malware itens dir = {input_malware_itens_dir}")
    debug(f"goodware itens dir = {input_goodware_itens_dir}")
    debug(f"malware batch dir = {input_malware_batch_dir}")
    debug(f"goodware batch dir = {input_goodware_batch_dir}")
    debug(f"cvs output file = {output_cvs}.")

    msg = validate_dirs(input_goodware_itens_dir, input_malware_itens_dir,
                        input_malware_batch_dir, input_goodware_batch_dir, output_cvs)

    if (len(msg) > 0):
        debug("Error in working directories.")
        debug(msg)

    debug("Loading json to dataframes.")

    dframes = []
    dframes = load_json_malware(input_malware_itens_dir)
    dframes += load_json_goodware(input_goodware_itens_dir)
    dframes += load_json_malware_batch(input_malware_batch_dir)
    dframes += load_json_goodware_batch(input_goodware_batch_dir)

    debug("Processing dataframes.")
    preprocessing_dataframes_save_to_cvs(output_cvs, dframes)


if __name__ == "__main__":
    main(sys.argv[1:])
