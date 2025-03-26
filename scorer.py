import argparse
import sys

def calc_score(lat_data):
    l = [x[0] / x[1] for x in lat_data]
    l.sort()
    score = sum(l)
    qt = [0.5, 0.75, 0.9, 0.95, 0.99]
    raw_values = [x[0] for x in lat_data]
    raw_values.sort()
    return score, [(q, raw_values[int(len(raw_values) * q)]) for q in qt]

def read_output(path):
    lat_data = []
    output = []
    with open(path) as fin:
        for line in fin:
            fields = line.split()
            lat_data.append((int(fields[2]), int(fields[1])))
            output.append(fields[:2] + fields[3:])
    return lat_data, output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate score")
    parser.add_argument("--output", type=str, help="Path to the file produced by runner", required=True)
    parser.add_argument("--correct", type=str, help="Path to the file with a correct answer")
    parser.add_argument("--tsc", type=int, help="Rate of TSC if you want to convert ticks to the elapsed time")
    args = parser.parse_args()

    lat_data, output = read_output(args.output)
    if args.correct:
        _, correct_output = read_output(args.correct)
        if output != correct_output:
            print("Files with results are different", file=sys.stderr)
            sys.exit(1)
    score, lat_values = calc_score(lat_data)
    print("{:.3f}".format(score))
    print("Measured on {} values".format(len(lat_data)), file=sys.stderr)
    for qt, val in lat_values:
        if not args.tsc:
            conv_val = ""
        else:
            conv_val = " ({:.3f} micro)".format(val / float(args.tsc))
        print("{:.2f}: {} ticks{}".format(qt, val, conv_val), file=sys.stderr)
