import pandas as pd
import argparse


def process(in_path: str, out_path: str):
    df = pd.read_csv(
        in_path,
        dtype={
            "ip_src": str,
            "ip_dst": str,
            "port_src": int,
            "port_dst": int,
            "n_packets": int,
            "n_bytes": int,
        },
    )
    sent_df = (
        df.groupby(["ip_src"])
        .agg({"n_packets": "sum", "n_bytes": "sum"})
        .reset_index(names="ip")
        .rename(columns={"n_packets": "n_packets_sent", "n_bytes": "n_bytes_sent"})
    )

    received_df = (
        df.groupby(["ip_dst"])
        .agg({"n_packets": "sum", "n_bytes": "sum"})
        .reset_index(names="ip")
        .rename(
            columns={
                "n_packets": "n_packets_received",
                "n_bytes": "n_bytes_received",
            }
        )
    )
    df = received_df.merge(sent_df, on=("ip")).fillna(0)
    df.to_csv(out_path, index=False)


def my_parse() -> (str, str):
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Show output")
    parser.add_argument("-o", "--out", help="Show output")

    args, unknown = parser.parse_known_args()

    in_path = args.input if args.input != None else unknown[0]

    out_path = args.out

    import os.path as pat

    if out_path == None:
        out_path = pat.join(
            pat.dirname(pat.abspath(in_path)),
            f"grouped-{pat.basename(in_path).removesuffix('.csv')}.csv",
        )
    elif pat.isdir(out_path):
        out_path = pat.join(
            out_path, f"grouped-{pat.basename(in_path).removesuffix('.csv')}.csv"
        )
    return in_path, out_path


def main():
    try:
        in_path, out_path = my_parse()
        process(in_path, out_path)
    except Exception as err:
        print(str(err))
        exit(-1)

    exit(0)


if __name__ == "__main__":
    main()
