import sys
import getopt
import os
import pandas as pd

GOODWARE_CLASSIFICATION = 0
MALWARE_CLASSIFICATION = 1
DEBUG = False


def debug(msg):
    if DEBUG:
        print(msg)


def preprocessing_dataframes_save_to_cvs(output_cvs, dframes):
    dfs_concant = pd.DataFrame()

    for dframe, class_df in dframes:
        for col_apk in dframe.columns:
            json_str = dframe[col_apk]['Static_analysis']
            df_static_analysis = pd.json_normalize(json_str)
            df_static_analysis.drop(
                [col for col in df_static_analysis.columns if is_to_drop(col)], axis=1, inplace=True)
            permissions = df_static_analysis.pop('Permissions')[0]

            for perm in permissions:
                df_static_analysis[perm] = 1 if perm not in df_static_analysis else 1 + \
                    df_static_analysis[perm]

            df_static_analysis['class'] = class_df
            dfs_concant = pd.concat([dfs_concant, df_static_analysis])

    dfs_concant.fillna(0, inplace=True)
    dfs_concant.reset_index(inplace=True)
    dfs_concant.drop(['index'], axis=1, inplace=True)

    dfs_concant.to_csv(os.path.join(dir, output_cvs))


def load_json_malware(input_dir):
    return load_json(input_dir, MALWARE_CLASSIFICATION)


def load_json_goodware(input_dir):
    return load_json(input_dir, GOODWARE_CLASSIFICATION)


def load_json(input_dir, classification):
    dframes = []

    with os.scandir(input_dir) as entries:
        for entry in entries:
            if entry.is_file() and entry.name.endswith('json'):
                pd_json = pd.read_json(entry.path)
                dframes.append((pd_json, classification))

    if len(dframes) == 0:
        print(
            f'No json file found: directory {input_dir}, classification {classification}')

    return dframes


def is_to_drop(col_name):
    return not (col_name.startswith('Permissions')
                or col_name.startswith('Opcodes')
                or col_name.startswith('API calls'))


def get_dirs_from_args(argv):
    input_goodware_dir = ''
    input_malware_dir = ''
    output_cvs = ''

    opts, args = getopt.getopt(argv, ['h'], [
                               "input-goodware-dir=", "input-malware-dir=", "output-dataframe-file="])

    for opt, arg in opts:
        if opt == '-h':
            print('preprocessing-dataset.py --input-goodware-dir=<dir> --input-malware-dir=<dir> --output-dataframe-file=<file>')
            sys.exit(-1)
        elif opt in ("--input-goodware-dir"):
            input_goodware_dir = arg
        elif opt in ("--input-malware-dir"):
            input_malware_dir = arg
        elif opt in ("--output-dataframe-file"):
            output_cvs = arg

    return (input_goodware_dir, input_malware_dir, output_cvs)


def validate_dirs(input_malware_dir, input_goodware_dir, output_cvs):

    error_message = ''

    if (not os.path.isdir(input_malware_dir)):
        error_message.join(f"Invalid malware directory ({input_malware_dir})")

    if (not os.path.isdir(input_goodware_dir)):
        error_message.join(
            f"Invalid goodware directory ({input_goodware_dir})")

    if (not os.path.isdir(output_cvs)):
        error_message.join(f"Invalid output directory ({output_cvs})")


def main(argv):

    debug("Starting preprocessing dataframes from json to cvs.")

    input_malware_dir = ''
    input_goodware_dir = ''
    output_cvs = ''

    debug("Validating working directories.")

    input_malware_dir, input_goodware_dir, output_cvs = get_dirs_from_args(
        argv)

    debug(
        f"Directories loaded: malware = {input_malware_dir}; goodware = {input_goodware_dir}; cvs output file = {output_cvs}.")

    try:
        validate_dirs(input_goodware_dir, input_malware_dir, output_cvs)
        debug("Error in working directories.")
    except Exception as error:
        print(error)
        sys.exit()

    debug("Loading json to dataframes.")

    dframes = []
    dframes = load_json_malware(input_malware_dir)
    dframes.append(load_json_goodware(input_goodware_dir))

    debug("Processing dataframes.")
    preprocessing_dataframes_save_to_cvs(output_cvs, dframes)


if __name__ == "__main__":
    main(sys.argv[1:])
