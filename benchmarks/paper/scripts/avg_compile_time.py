import re
import sys


def process_log_file(log_file_path):
    pattern = r"Total compilation time: \d+ ms \((\d+) [μµ]s\)"

    times_in_microseconds = []
    total_compilation_time_lines = []

    try:
        with open(log_file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if "Total compilation time" not in line:
                    continue
                total_compilation_time_lines.append(line.strip())
                match = re.search(pattern, line)
                if match:
                    times_in_microseconds.append(int(match.group(1)))
                else:
                    print(f"pattern mismatch: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return

    if not total_compilation_time_lines:
        print(f"No 'Total compilation time' sentences found in '{log_file_path}'.")
        return

    print("\nAll 'Total compilation time' sentences:")
    for sentence in total_compilation_time_lines:
        print(sentence)

    # Group every 10 samples and report the per-group average in ms.
    print("\nlen: ", len(total_compilation_time_lines))
    averages_in_milliseconds = []
    for i in range(0, len(times_in_microseconds), 10):
        group = times_in_microseconds[i:i + 10]
        if group:
            averages_in_milliseconds.append(sum(group) / len(group) / 1000.0)

    if averages_in_milliseconds:
        print("\nGroup averages (10 samples per group, ms):")
        for idx, avg_ms in enumerate(averages_in_milliseconds, start=1):
            print(f"Group {idx}: {avg_ms:.3f} ms")
    else:
        print("\nNo microsecond values extracted; cannot compute averages.")


if __name__ == "__main__":
    process_log_file(sys.argv[1] if len(sys.argv) > 1 else "dtvm_compile_time.txt")
