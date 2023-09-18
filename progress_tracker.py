from util import bytes2human, print_message
from multiprocessing import Queue
from time import time

file_name_queue = Queue()
bytes_processed_queue = Queue()


def format_file_name(file_name: str):
    if len(file_name) > 23:
        return file_name[:10] + "..." + file_name[-10:]
    return file_name


def print_progress(curr_file_name: str, num_files_completed: int, data_rate: str, data_total: str, elapsed_time: str):
    message = f"Processing {format_file_name(curr_file_name)} | {data_rate}/sec | {num_files_completed} files, {data_total} total | Elapsed time: {elapsed_time}"
    print_message(message)


def format_elapsed_time(seconds):
    return f"{int(seconds / 3600):02d}:{(int(seconds/60) % 60):02d}:{(int(seconds) % 60):02d}"


def track_progress():
    start_time = time()
    prev_time = start_time
    seconds_elapsed = 0
    curr_file_name = "<none>"
    bytes_this_second = 0
    bytes_processed = 0
    num_files_processed = 0

    while True:  # this exits when the forked process is killed
        curr_time = time()
        try:
            curr_file_name = file_name_queue.get_nowait()
            num_files_processed += 1
        except Exception:
            pass
        while not bytes_processed_queue.empty():
            additional_bytes = bytes_processed_queue.get_nowait()
            bytes_this_second += additional_bytes
            bytes_processed += additional_bytes

        if curr_time - prev_time >= 1:  # only run this once/sec
            print_progress(
                curr_file_name=curr_file_name,
                num_files_completed=num_files_processed,
                data_rate=bytes2human(bytes_this_second),
                data_total=bytes2human(bytes_processed),
                elapsed_time=format_elapsed_time(seconds_elapsed))
            prev_time = curr_time
            seconds_elapsed = curr_time - start_time
            bytes_this_second = 0