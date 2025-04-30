import argparse
import sys
import difflib

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
    parser.add_argument("--check-only", type=int, help="Don't calc score, just check results", default=0)
    args = parser.parse_args()

    lat_data, output = read_output(args.output)
    if args.correct:
        _, correct_output = read_output(args.correct)
        if output != correct_output:
            print("Files with results are different:", file=sys.stderr)
            # Convert lists of lists to lists of strings for diffing
            output_lines = [' '.join(map(str, line)) for line in output]
            correct_output_lines = [' '.join(map(str, line)) for line in correct_output]
            diff = difflib.unified_diff(
                correct_output_lines,
                output_lines,
                fromfile=args.correct,
                tofile=args.output,
                lineterm='\n',
            )
            for line in diff:
                sys.stderr.write(line) # Already includes newline
            sys.exit(1)
        if args.check_only:
            sys.exit(0)
    score, lat_values = calc_score(lat_data)
    print("{:.3f}".format(score))
    print("Measured on {} values".format(len(lat_data)), file=sys.stderr)
    for qt, val in lat_values:
        if not args.tsc:
            conv_val = ""
        else:
            conv_val = " ({:.3f} micro)".format(val / float(args.tsc))
        print("{:.2f}: {} ticks{}".format(qt, val, conv_val), file=sys.stderr)
