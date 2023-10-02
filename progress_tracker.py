from queue import Empty
import sys
from typing import Callable, List, NoReturn
from util import bytes2human, format_elapsed_time, print_message
from multiprocessing import Queue
from time import sleep, time
import signal

FILE_NAME_VISIBLE_LENGTH = 15
DATA_FIELD_WIDTH: int = 7  # max length should be 7 (e.g. "1023 GB")


def format_file_name(file_name: str, length: int) -> str:
    ellipses: str = "..."
    if len(file_name) > length:
        prefix_length = int((length - len(ellipses))/2)
        suffix_length = length - len(ellipses) - prefix_length
        return file_name[:prefix_length] + ellipses + file_name[-suffix_length:]
    else:
        return file_name


def on_terminate(queues: List[Queue]) -> None:
    for q in queues:
        try:
            while not q.empty():
                q.get_nowait()
        except Empty:
            pass
    sys.exit(0)  # exit from this subprocess


def track_progress(file_name_queue: Queue, bytes_processed_queue: Queue, print_func: Callable) -> NoReturn:
    start_time = time()
    prev_time = start_time
    seconds_elapsed = 0
    curr_file_name = "<none>"
    bytes_this_second = 0
    bytes_processed = 0
    num_files_processed = 0

    # since the atexit module doesn't work for subprocesses, I have to capture the SIGTERM signal
    signal.signal(signal.SIGTERM, lambda signalnum, frame: on_terminate([file_name_queue, bytes_processed_queue]))

    while True:
        sleep(0.1)
        curr_time = time()
        while not file_name_queue.empty():
            curr_file_name = file_name_queue.get_nowait()
            num_files_processed += 1
        while not bytes_processed_queue.empty():
            additional_bytes = bytes_processed_queue.get_nowait()
            bytes_this_second += additional_bytes
            bytes_processed += additional_bytes

        if curr_time - prev_time >= 1:  # only run this once/sec
            data_rate=bytes2human(bytes_this_second)
            data_total=bytes2human(bytes_processed)
            elapsed_time=format_elapsed_time(seconds_elapsed)
            print_func(curr_file_name, num_files_processed, data_rate, data_total, elapsed_time)
            prev_time = curr_time
            seconds_elapsed = curr_time - start_time
            bytes_this_second = 0


def print_file_hash_status(curr_file_name: str, num_files_processed: int, data_rate: str, data_total: str, elapsed_time: str) -> None:
    data_rate_padding:str  = " "*(DATA_FIELD_WIDTH - len(data_rate))
    data_total_padding: str = " "*(DATA_FIELD_WIDTH - len(data_total))
    file_name_fixed_width: str = format_file_name(curr_file_name, FILE_NAME_VISIBLE_LENGTH) + " "*(FILE_NAME_VISIBLE_LENGTH - len(curr_file_name))
    message = f"Processing {file_name_fixed_width} | {data_rate}/sec{data_rate_padding} | {num_files_processed} files, {data_total} total{data_total_padding} | Elapsed time: {elapsed_time}"
    print_message(message)


# Not all inputs are used here but this function needs the same signature as as print_file_hash_status
def print_fs_scan_status(curr_file_name: str, num_files_processed: int, data_rate: str, data_total: str, elapsed_time: str) -> None:
    print_message(f"Found {num_files_processed} files | Elapsed time: {elapsed_time}", line_width=80)


def track_file_hash_progress(file_name_queue: Queue, bytes_processed_queue: Queue) -> NoReturn:
    track_progress(file_name_queue, bytes_processed_queue, print_file_hash_status)


def track_fs_scan_progress(file_name_queue: Queue) -> NoReturn:
    track_progress(file_name_queue, Queue(), print_fs_scan_status)
